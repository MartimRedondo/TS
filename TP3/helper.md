# Sistema Bell-LaPadula (BLP) - Controlo de Acesso Multi-nível

## Visão Geral

Este projeto implementa o modelo de controlo de acesso Bell-LaPadula (BLP) com extensões práticas para resolver as limitações do modelo teórico original. O sistema garante a confidencialidade através das propriedades fundamentais do BLP e introduz funcionalidades como utilizadores de confiança, desclassificação controlada e auditoria completa.

## Arquitetura do Sistema

### Componentes Principais

1. **Motor BLP (`blp_access_control.py`)**: Implementação core do modelo com todas as estruturas de dados e lógica de controlo de acesso
2. **Servidor REST (`blp_server.py`)**: API HTTP para acesso remoto ao sistema
3. **Cliente CLI (`blp_client.py`)**: Interface de linha de comandos para interação
4. **Demonstração (`blp_example_usage.py`)**: Exemplos de utilização e t