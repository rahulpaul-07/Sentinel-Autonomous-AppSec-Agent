"""
hello_llm.py
------------
A tiny script to prove the model layer works end to end.
Run it from the project root with:  python hello_llm.py
"""

from sentinel.llm import LLMClient


def main() -> None:
    # Create the client. With no model argument, it reads SENTINEL_MODEL from .env.
    client = LLMClient()
    print(f"Using model: {client.model}\n")

    # Ask the model a simple security question. `system` sets its role/personality.
    result = client.complete(
        prompt="In one sentence, what is a SQL injection vulnerability?",
        system="You are a concise, precise security tutor.",
    )

    # `result` is our LLMResponse object: text + token counts + cost.
    print("--- Model reply ---")
    print(result.text)
    print("\n--- Stats ---")
    print(f"Prompt tokens:     {result.prompt_tokens}")
    print(f"Completion tokens: {result.completion_tokens}")
    print(f"Estimated cost:    ${result.cost_usd:.6f}")


if __name__ == "__main__":
    main()