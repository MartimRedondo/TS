# Makefile para o Sistema BLP
# Implementação do modelo Bell-LaPadula com base de dados chave-valor e reforço de sessões

# Variáveis
PYTHON = python3
PIP = pip3
SERVER_FILE = server.py
CLIENT_FILE = client.py
SESSION_REFRESHER_FILE = session_refresher.py
SECURE_CLEANUP_FILE = secure_cleanup.py
DB_MANAGER_FILE = database_manager.py
POPULATE_FILE = populate_database.py
GENERATE_CERTS_FILE = generate_certificates.py
DB_FILE = blp_database.json
SERVER_PORT = 5001
SERVER_HOST = localhost
SERVER_URL = https://$(SERVER_HOST):$(SERVER_PORT)
CERT_DIR = ./certs
AUDIT_LOG = blp_audit.log
LOGS_DIR = ./logs

# Alvo padrão
.PHONY: all
all: install setup

# Ajuda
.PHONY: help
help:
	@echo "Makefile para o Sistema BLP - Modelo Bell-LaPadula"
	@echo ""
	@echo "Alvos disponíveis:"
	@echo "  all                - Instala dependências e configura o ambiente"
	@echo "  install            - Instala todas as dependências necessárias"
	@echo "  setup              - Configura o ambiente e inicializa a base de dados"
	@echo "  server             - Inicia o servidor BLP (requer certificados)"
	@echo "  client             - Inicia o cliente BLP (requer certificados)"
	@echo "  certificates       - Gera certificados TLS para autenticação mútua"
	@echo "  logs               - Visualiza o log de auditoria geral em tempo real"
	@echo "  logs-user USER=nome - Visualiza o log específico de um utilizador"
	@echo "  logs-list          - Lista todos os logs de utilizadores disponíveis"
	@echo "  interactive-tests  - Executa testes interativos com pexpect"
	@echo "  clean              - Remove ficheiros temporários e base de dados"
	@echo "  clean-all          - Remove todos os ficheiros gerados, incluindo certificados"
	@echo "  help               - Mostra esta ajuda"
	@echo ""
	@echo "Exemplos de uso:"
	@echo "  make                    - Instala dependências e configura o ambiente"
	@echo "  make certificates       - Gera certificados TLS para servidor e cliente"
	@echo "  make server             - Inicia o servidor em um terminal"
	@echo "  make client             - Inicia o cliente em outro terminal"
	@echo "  make logs               - Visualiza o log de auditoria geral"
	@echo "  make logs-user USER=alice - Visualiza o log específico do utilizador 'alice'"
	@echo "  make logs-list          - Lista todos os logs de utilizadores disponíveis"

# Instalação de dependências
.PHONY: install
install:
	@echo "Instalando dependências..."
	$(PIP) install --upgrade pip
	$(PIP) install flask flask-cors cryptography tinydb requests flask-limiter
	@echo "Dependências instaladas com sucesso."

# Configuração inicial
.PHONY: setup
setup:
	@echo "Configurando o ambiente..."
	@if [ -f $(DB_FILE) ]; then \
		echo "Base de dados já existe. Para recriar, execute 'make clean' primeiro."; \
	else \
		echo "Inicializando a base de dados..."; \
		$(PYTHON) $(POPULATE_FILE); \
	fi
	@mkdir -p $(LOGS_DIR)
	@echo "Configuração concluída."

# Gerar certificados TLS para autenticação mútua
.PHONY: certificates
certificates:
	@echo "Gerando certificados TLS para autenticação mútua..."
	@if [ ! -f $(GENERATE_CERTS_FILE) ]; then \
		echo "Erro: Ficheiro $(GENERATE_CERTS_FILE) não encontrado."; \
		exit 1; \
	fi
	@mkdir -p $(CERT_DIR)
	$(PYTHON) $(GENERATE_CERTS_FILE) --cert-dir $(CERT_DIR)
	@echo "Certificados gerados com sucesso em $(CERT_DIR)"
	@echo "Para usar os certificados com o servidor:"
	@echo "  export CERT_DIR=$(CERT_DIR)"
	@echo "Para usar os certificados com o cliente:"
	@echo "  ./$(CLIENT_FILE) --server $(SERVER_URL) --ca-cert $(CERT_DIR)/ca.crt --client-cert $(CERT_DIR)/client.crt --client-key $(CERT_DIR)/client.key"

# Iniciar o servidor com certificados TLS
.PHONY: server
server:
	@echo "Verificando se os certificados existem..."
	@if [ ! -d $(CERT_DIR) ] || [ ! -f $(CERT_DIR)/ca.crt ] || [ ! -f $(CERT_DIR)/server.crt ] || [ ! -f $(CERT_DIR)/server.key ]; then \
		echo "Erro: Certificados não encontrados. Execute 'make certificates' primeiro."; \
		exit 1; \
	fi
	@echo "Iniciando o servidor BLP com TLS na porta $(SERVER_PORT)..."
	@echo "Para parar o servidor, pressione Ctrl+C"
	@echo "Os logs serão gravados em $(AUDIT_LOG)"
	CERT_DIR=$(CERT_DIR) $(PYTHON) $(SERVER_FILE)

# Iniciar o cliente com certificados TLS
.PHONY: client
client:
	@echo "Verificando se os módulos auxiliares existem..."
	@if [ ! -f $(CLIENT_FILE) ] || [ ! -f $(SESSION_REFRESHER_FILE) ] || [ ! -f $(SECURE_CLEANUP_FILE) ]; then \
		echo "Erro: Ficheiros do cliente não encontrados."; \
		echo "Certifique-se de que os seguintes ficheiros existem:"; \
		echo "  - $(CLIENT_FILE)"; \
		echo "  - $(SESSION_REFRESHER_FILE)"; \
		echo "  - $(SECURE_CLEANUP_FILE)"; \
		exit 1; \
	fi
	@echo "Verificando se os certificados existem..."
	@if [ ! -d $(CERT_DIR) ] || [ ! -f $(CERT_DIR)/ca.crt ] || [ ! -f $(CERT_DIR)/client.crt ] || [ ! -f $(CERT_DIR)/client.key ]; then \
		echo "Erro: Certificados não encontrados. Execute 'make certificates' primeiro."; \
		exit 1; \
	fi
	@echo "Iniciando o cliente BLP com TLS conectando a $(SERVER_URL)..."
	@chmod +x $(CLIENT_FILE)
	./$(CLIENT_FILE) --server $(SERVER_URL) --ca-cert $(CERT_DIR)/ca.crt --client-cert $(CERT_DIR)/client.crt --client-key $(CERT_DIR)/client.key --refresh-interval 300 --verbose

# Visualizar log de auditoria geral em tempo real
.PHONY: logs
logs:
	@echo "Visualizando log de auditoria geral em tempo real..."
	@if [ ! -f $(AUDIT_LOG) ]; then \
		echo "Aviso: Ficheiro de log de auditoria não existe ainda."; \
		touch $(AUDIT_LOG); \
	fi
	tail -f $(AUDIT_LOG)

# Visualizar log específico de um utilizador
.PHONY: logs-user
logs-user:
	@if [ -z "$(USER)" ]; then \
		echo "Erro: Nome de utilizador não especificado."; \
		echo "Uso: make logs-user USER=nome"; \
		exit 1; \
	fi
	@echo "Visualizando log do utilizador $(USER) em tempo real..."
	@if [ ! -f "$(LOGS_DIR)/user_$(USER).log" ]; then \
		echo "Aviso: Ficheiro de log para o utilizador $(USER) não existe ainda."; \
		touch "$(LOGS_DIR)/user_$(USER).log"; \
	fi
	tail -f "$(LOGS_DIR)/user_$(USER).log"

# Listar todos os logs de utilizadores disponíveis
.PHONY: logs-list
logs-list:
	@echo "Logs de utilizadores disponíveis:"
	@if [ ! -d "$(LOGS_DIR)" ] || [ -z "$(shell ls -A $(LOGS_DIR) 2>/dev/null)" ]; then \
		echo "  Nenhum log de utilizador encontrado."; \
	else \
		ls -1 $(LOGS_DIR) | grep "^user_" | sed 's/^user_/  /;s/\.log$$//' | sort; \
	fi

# Testes automáticos com pexpect
.PHONY: interactive-tests
interactive-tests:
	@echo "Executando testes interativos com pexpect..."
	@if [ ! -d $(CERT_DIR) ] || [ ! -f $(CERT_DIR)/ca.crt ] || [ ! -f $(CERT_DIR)/client.crt ] || [ ! -f $(CERT_DIR)/client.key ]; then \
		echo "Erro: Certificados não encontrados. Execute 'make certificates' primeiro."; \
		exit 1; \
	fi
	$(PYTHON) -m unittest tests/test.py

# Limpar ficheiros temporários e base de dados
.PHONY: clean
clean:
	@echo "Limpando ficheiros temporários e base de dados..."
	@if [ -f $(DB_FILE) ]; then \
		rm -f $(DB_FILE); \
		echo "Base de dados removida."; \
	fi
	@if [ -f $(TEST_DB_FILE) ]; then \
		rm -f $(TEST_DB_FILE); \
		echo "Base de dados de teste removida."; \
	fi
	@rm -f encryption_key.json
	@rm -f *.pyc
	@rm -rf __pycache__
	@echo "Limpeza concluída."

# Limpar tudo, incluindo certificados e logs
.PHONY: clean-all
clean-all: clean
	@echo "Limpando certificados..."
	@if [ -d $(CERT_DIR) ]; then \
		rm -rf $(CERT_DIR); \
		echo "Diretório de certificados removido."; \
	fi
	@echo "Limpando logs..."
	@if [ -f $(AUDIT_LOG) ]; then \
		rm -f $(AUDIT_LOG); \
		echo "Log de auditoria geral removido."; \
	fi
	@if [ -d $(LOGS_DIR) ]; then \
		rm -rf $(LOGS_DIR); \
		echo "Diretório de logs de utilizadores removido."; \
	fi
	@echo "Limpeza completa concluída."
