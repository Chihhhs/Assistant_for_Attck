'''
'''
from langchain_community.chat_models import ChatOllama
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages.ai import AIMessage
from langchain_core.messages.human import HumanMessage
from langchain_community.llms.huggingface_pipeline import HuggingFacePipeline

import os
import yaml
import streamlit as st

st.title("ATT&CK Assistant")

def init_chat_history() -> ChatPromptTemplate:
    if 'chat_history' not in st.session_state:
        template = ChatPromptTemplate.from_messages([
            ('system', "You are an Assistant for Att&ck."), 
        ])
        st.session_state['chat_history'] = template
    else:
        template = st.session_state['chat_history']
    return template

chat_tmp = init_chat_history()

llm = HuggingFacePipeline.from_model_id(
    model_id="Xcvddax/Attack-techniques-full-gemma",
    task="text-generation",
    pipeline_kwargs={"max_new_tokens": 10},
)

user_input = st.chat_input("Say something")
chain = chat_tmp | llm | StrOutputParser()

if user_input:
    with st.status("Thinking..."):
        chat_tmp.append(HumanMessage(user_input))
        response = chain.invoke({})
        chat_tmp.append(AIMessage(response))
        st.session_state['chat_history'] = chat_tmp

for message in st.session_state['chat_history'].messages:
    if isinstance(message, HumanMessage):
        with st.chat_message("user"):
            st.write(message.content)
    elif isinstance(message, AIMessage):
        with st.chat_message("assistant"):
            st.write(message.content)
    