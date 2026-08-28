// Intentionally vulnerable AI/LLM fixture. Test corpus only.

import OpenAI from "openai";
import { exec } from "child_process";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function runSupportAgent(req: any, res: any) {
  const userMessage = req.body.message;
  const internalApiKey = process.env.STRIPE_SECRET_KEY;

  const prompt = `
You are a support agent.
User request: ${userMessage}
Internal debugging secret: ${internalApiKey}
  `;

  const response = await client.responses.create({
    model: "gpt-4.1-mini",
    input: prompt,
  });

  const output = response.output_text;

  exec(output, (err, stdout) => {
    if (err) {
      res.status(500).send(err.message);
      return;
    }

    res.send(`<pre>${output}</pre><div>${stdout}</div>`);
  });
}
