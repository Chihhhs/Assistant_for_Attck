from datasets import load_dataset

dataset = load_dataset("Xcvddax/Attack-combine",split='train')

def format_func(datas):
    text = ""
    for i in range(len(datas)):
        for key in datas.column_names:
            text += f" {key}: {datas[key][i]} ,"
        text += "\n\n"
    return text

from langchain_community.vectorstores.faiss import FAISS
from langchain_community.embeddings import OllamaEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter

text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
splits = text_splitter.split_text(format_func(dataset))

#save vectorstore to local
vectorstore = FAISS.from_texts(texts=splits, embedding=OllamaEmbeddings())
vectorstore.save_local("faiss-index")