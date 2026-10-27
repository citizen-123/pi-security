// A Models decorator that removes known credential values from provider errors before pi-durable stores them.
import { type AssistantMessage, type AssistantMessageEventStream, createAssistantMessageEventStream } from "@earendil-works/pi-ai";

export function redactingModels<M extends object>(models: M, secrets: readonly string[]): M {
	const redact = (text: string) => secrets.reduce((acc, secret) => (secret.length >= 8 ? acc.split(secret).join("[REDACTED]") : acc), text);
	const fix = (message: AssistantMessage): AssistantMessage =>
		message.errorMessage === undefined ? message : { ...message, errorMessage: redact(message.errorMessage) };
	const wrapStream = (source: AssistantMessageEventStream) => {
		const target = createAssistantMessageEventStream();
		void (async () => {
			for await (const event of source) {
				if (event.type === "error") target.push({ ...event, error: fix(event.error) });
				else if (event.type === "done") target.push({ ...event, message: fix(event.message) });
				else target.push(event);
			}
			target.end();
		})();
		return target;
	};
	return new Proxy(models, {
		get(target, property, receiver) {
			const value = Reflect.get(target, property, receiver);
			if (typeof value !== "function") return value;
			if (property === "streamSimple" || property === "streamDeferred") {
				return (...args: unknown[]) => wrapStream(value.apply(target, args));
			}
			if (property === "completeSimple" || property === "fetchDeferred") {
				return async (...args: unknown[]) => fix(await value.apply(target, args));
			}
			return value.bind(target);
		},
	});
}
