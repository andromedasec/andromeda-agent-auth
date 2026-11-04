"""A LangGraph agent whose MCP tools go through the Andromeda Agent Gateway,
authenticated with its registered key and DPoP.

    pip install './sdk/python/andromeda-agent-auth[langgraph]' langchain-anthropic

    export ANDROMEDA_AGENT_CLIENT_ID=<the agent's OAuth client id>
    export ANDROMEDA_TOKEN_URL=https://<apiserver>/oauth/gateway/<gateway host>/token
    export ANDROMEDA_GATEWAY_MCP_URL=https://<gateway>/mcp
    export ANDROMEDA_AGENT_PRIVATE_KEY_FILE=agent-key.pem
    export AGENT_MODEL=<a LangChain chat model id, e.g. anthropic:<model name>>

    python examples/langgraph_agent.py "what tools do you have?"

Without AGENT_MODEL it only lists the tools the gateway lets this agent see.
"""

import asyncio
import os
import sys

from langchain_mcp_adapters.client import MultiServerMCPClient

from andromeda_agent_auth import AgentAuth, keys


async def main(question: str) -> None:
    auth = AgentAuth(
        client_id=os.environ["ANDROMEDA_AGENT_CLIENT_ID"],
        token_url=os.environ["ANDROMEDA_TOKEN_URL"],
        key=keys.load_env(),
    )
    client = MultiServerMCPClient(
        {
            "gateway": {
                "transport": "streamable_http",
                "url": os.environ["ANDROMEDA_GATEWAY_MCP_URL"],
                "auth": auth,
            }
        }
    )
    tools = await client.get_tools()
    print("tools:", ", ".join(t.name for t in tools) or "(none)")

    model = os.environ.get("AGENT_MODEL")
    if not model:
        return
    from langchain.chat_models import init_chat_model
    from langgraph.prebuilt import create_react_agent

    agent = create_react_agent(init_chat_model(model), tools)
    result = await agent.ainvoke({"messages": [{"role": "user", "content": question}]})
    print(result["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(main(" ".join(sys.argv[1:]) or "What tools do you have?"))
