'''
'''
from langchain_community.chat_models import ChatOllama
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages.ai import AIMessage
from langchain_core.messages.human import HumanMessage
from langchain_community.llms.huggingface_pipeline import HuggingFacePipeline

from transformers import GenerationConfig

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

generation_config = GenerationConfig(
    max_length=400,                   # 設置最大生成長度
    min_length=100,                    # 設置最小生成長度以確保生成的文本足夠長
    do_sample=True,                   # 啟用採樣模式
    temperature=0.7,                  # 設置溫度以控制生成文本的隨機性
    early_stopping=True,              # 啟用早停以生成完整句子
    no_repeat_ngram_size=3,           # 防止重複3-gram的出現
    repetition_penalty=1.2,           # 設置重複懲罰
    num_beams=5,                      # 使用 beam search 並設置 beam 數量
    length_penalty=1.0                # 長度懲罰，控制生成文本的長度
)


llm = HuggingFacePipeline.from_model_id(
    model_id="Xcvddax/Attack-techniques-full-gemma",
    task="text-generation",
    pipeline_kwargs=generation_config.to_dict(),
)

# llm.save("model/")

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
    