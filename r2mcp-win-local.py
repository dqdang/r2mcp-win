from creds import base_url
from mcp.server.fastmcp import FastMCP

import aiohttp
import asyncio

mcp = FastMCP("r2mcp-win")

async def r2_ai_send(prompt):
    url = "http://{}:1234/api/v1/chat".format(base_url)
    payload = {
        "model": "openai/gpt-oss-20b",
        "reasoning": "low",
        "input": prompt,
        "stream": False
    }
    headers = {"Content-Type": "application/json"}

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers) as response:
            data = await response.json()
            return data
    return None

def run_r2pipe(extracted_file):
    response = ""
    r2 = r2pipe.open("/bin/ls")
    r2.cmd('aa')
    response += r2.cmd("afl")
    response += r2.cmdj("aflj")            # evaluates JSONs and returns an object
    response += r2.cmdj("ij").core.format  # shows file format
    r2.quit()
    return response

async def extract_file(question):
    query_template =  """
    From the user's question, find the provided path and return it.
    Question: {question}
    """
    prompt = query_template.format(question=question)

    response = await r2_ai_send(prompt)

    return response["output"][1]["content"] if response else ""

@mcp.tool()
async def answer_database_question(question):
    extracted_file = await extract_file(question)
    result = run_r2pipe(extracted_file)
    return result

def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    asyncio.run(main())
