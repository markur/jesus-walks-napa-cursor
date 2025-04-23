import OpenAI from "openai";
import type { ModelConfig } from "@shared/schema";

if (!process.env.OPENAI_API_KEY) {
  throw new Error("Missing required env var: OPENAI_API_KEY");
}

// the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export async function generateChatResponse(
  messages: ChatMessage[],
  modelConfig: ModelConfig
): Promise<string> {
  try {
    const completion = await openai.chat.completions.create({
      model: modelConfig.modelId,
      messages,
      temperature: Number(modelConfig.temperature),
      max_tokens: modelConfig.maxTokens,
    });

    return completion.choices[0].message.content || '';
  } catch (error: any) {
    console.error('OpenAI API Error:', error);
    throw new Error(`Failed to generate response: ${error.message}`);
  }
}

export async function countTokens(text: string): Promise<number> {
  // Approximate token count (1 token ≈ 4 chars in English)
  return Math.ceil(text.length / 4);
}
