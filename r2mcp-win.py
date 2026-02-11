from copilot import CopilotClient
from datetime import datetime, timedelta
from langchain_community.utilities import SQLDatabase
from mcp.server.fastmcp import FastMCP
# from fastmcp import FastMCP

import asyncio
import os
import r2pipe

mcp = FastMCP("r2mcp-win")

async def create_llm():
    llm = CopilotClient({
        "log_level": "info",     # default: "info"
        "auto_start": True,      # default: True
        "auto_restart": False,   # default: True
    })
    await llm.start()

    session = await llm.create_session(
        {
            "model": "gpt-4.1",
            "streaming": True,
            "infinite_sessions": {"enabled": False},
            "system_message": {
                "mode": "replace",
                "content": """
                """
            }
        }
    )

    return llm, session

async def stop_llm(llm, session):
    await session.destroy()
    await llm.stop()

def run_r2pipe(extracted_file):
    response = ""
    r2 = r2pipe.open("/bin/ls")
    r2.cmd('aa')
    response += r2.cmd("afl")
    response += r2.cmdj("aflj")            # evaluates JSONs and returns an object
    response += r2.cmdj("ij").core.format  # shows file format
    r2.quit()
    return response

async def extract_file(llm, session, question):
    query_template =  """
    From the user's question, find the provided path and return it.
    Question: {question}
    """
    prompt = query_template.format(question=question)

    done = asyncio.Event()
    response = []

    def on_event(event):
        if event.type.value == "assistant.message_delta":
            # Streaming message chunk
            delta = event.data.delta_content or ""
        elif event.type.value == "assistant.reasoning_delta":
            # Streaming reasoning chunk (if model supports reasoning)
            delta = event.data.delta_content or ""
        elif event.type.value == "assistant.message":
            # Final message - complete content
            response.append(event.data.content)
        elif event.type.value == "assistant.reasoning":
            # Final reasoning content (if model supports reasoning)
            pass
        elif event.type.value == "session.idle":
            # Session finished processing
            done.set()

    unsubscribe = session.on(on_event)
    await session.send({"prompt": prompt})
    await done.wait()
    unsubscribe()

    return response[0] if response else ""

# @mcp.tool
@mcp.tool()
async def answer_database_question(question):
    llm, session = await create_llm()
    extracted_file = await extract_file(llm, session, question)
    result = run_r2pipe(extracted_file)
    await stop_llm(llm, session)
    return result

def main():
    # Uses stdio transport by default
    mcp.run(transport="stdio")

if __name__ == "__main__":
    asyncio.run(main())
