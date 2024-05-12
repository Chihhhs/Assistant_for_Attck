from datasets import load_dataset

dataset = load_dataset("jiandong/crimson-attck-vectors",split='train')
format_func = lambda data: f"id: {data['id']}, attck_id: {data['attck_id']}, 'attck_name{data['attck_name']}', 'description{data['description']}', 'kill_chain_phases{data['kill_chain_phases']}', 'domains{data['domains']}', 'tactic_type{data['tactic_type']}'"

from dotenv import load_dotenv
import os 
load_dotenv()


from langchain_community.vectorstores.faiss import FAISS
from langchain_community.embeddings import OllamaEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter

text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
splits = text_splitter.split_text(format_func(dataset))

# graph
# embedding 
vectorstore = FAISS.from_texts(texts=splits, embedding=OllamaEmbeddings())
vectorstore.save_local("faiss-index")
new_vector = FAISS.load_local("faiss-index",OllamaEmbeddings(),allow_dangerous_deserialization=True)

retriever = new_vector.as_retriever()

from langchain import hub
prompt = hub.pull("rlm/rag-prompt")
example_messages = prompt.invoke(
    {"context": "filler context", "question": "filler question"}
).to_messages()
example_messages
# print(example_messages[0].content)

from langchain_community.llms.ollama import Ollama

llm = Ollama()
# llm.invoke("test")

from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough

def format_docs(docs):
    return "\n\n".join( doc.page_content for doc in docs)


rag_chain = (
    {"context": retriever | format_docs, "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)


""" ref
T1651	Cloud Administration Command	Adversaries may abuse cloud management services to execute commands within virtual machines. Resources such as AWS Systems Manager, Azure RunCommand, and Runbooks allow users to remotely run scripts in virtual machines by leveraging installed virtual machine agents.
"""

"""
What are cloud management services, and how can they be abused by adversaries?
How do resources like AWS Systems Manager, Azure RunCommand, and Runbooks allow users to execute commands within virtual machines?
What are the potential risks of adversaries leveraging cloud management services to execute commands?
How can one identify and prevent adversaries from abusing cloud management services for command execution?
Do cloud providers offer security measures to prevent adversaries from abusing these management services?
"""

ans = rag_chain.invoke("What are cloud management services, and how can they be abused by adversaries?")

import translators as ts
print(ts.translate_text(query_text=ans, translator='google', from_language= 'en', to_language='zh-TW'))