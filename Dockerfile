# Use uma imagem base com Python.
FROM python:3.12-slim

# Defina o diretório de trabalho dentro do container
WORKDIR /app

# Instale o pacote postgresql-client
RUN apt-get update && apt-get install -y postgresql-client

# Copie o arquivo de requisitos e instale as dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie o restante do código do aplicativo
COPY . .

# Exponha a porta do aplicativo
EXPOSE 3000

# Comando para rodar o aplicativo (corrigido)
CMD ["python", "app.py"]