#!/usr/bin/env python3
"""
Módulo de refresh de sessão para o cliente BLP.
Implementa um mecanismo de refresh periódico de sessão em background.
"""

import threading
import time
import logging
from typing import Optional, Callable

# Configuração de logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SessionRefresher')

class SessionRefresher:
    """
    Classe responsável por manter a sessão ativa através de refreshes periódicos.
    Executa em background como um thread daemon.
    """
    
    def __init__(self, 
                 refresh_callback: Callable[[], bool], 
                 interval: int = 600,  # 10 minutos por padrão
                 max_retries: int = 3,
                 retry_delay: int = 30,
                 verbose: bool = False):
        """
        Inicializa o refresher de sessão.
        
        Args:
            refresh_callback: Função a ser chamada para refresh da sessão
            interval: Intervalo entre refreshes em segundos (padrão: 600s = 10min)
            max_retries: Número máximo de tentativas em caso de falha
            retry_delay: Tempo de espera entre tentativas em segundos
            verbose: Se True, imprime mensagens de debug
        """
        self.refresh_callback = refresh_callback
        self.interval = interval
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.verbose = verbose
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self._last_refresh_time = 0
        self._failed_attempts = 0
        
    def start(self) -> bool:
        """
        Inicia o thread de refresh em background.
        
        Returns:
            bool: True se iniciado com sucesso, False caso contrário
        """
        if self.thread and self.thread.is_alive():
            if self.verbose:
                logger.info("Refresh thread já está em execução")
            return True
            
        self.running = True
        self.thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self.thread.start()
        
        if self.verbose:
            logger.info(f"Refresh de sessão iniciado (intervalo: {self.interval}s)")
        return True
        
    def stop(self) -> None:
        """
        Para o thread de refresh.
        """
        self.running = False
        if self.thread and self.thread.is_alive():
            # Não precisamos de join aqui pois o thread é daemon
            if self.verbose:
                logger.info("Refresh de sessão parado")
        self.thread = None
        self._failed_attempts = 0
        
    def is_running(self) -> bool:
        """
        Verifica se o refresher está em execução.
        
        Returns:
            bool: True se estiver em execução, False caso contrário
        """
        return self.running and self.thread and self.thread.is_alive()
    
    def get_status(self) -> dict:
        """
        Retorna o estado atual do refresher.
        
        Returns:
            dict: Dicionário com informações de estado
        """
        return {
            "running": self.is_running(),
            "interval": self.interval,
            "last_refresh": self._last_refresh_time,
            "failed_attempts": self._failed_attempts
        }
        
    def set_interval(self, seconds: int) -> None:
        """
        Altera o intervalo de refresh.
        
        Args:
            seconds: Novo intervalo em segundos
        """
        if seconds < 60:
            logger.warning(f"Intervalo muito curto ({seconds}s), mínimo recomendado é 60s")
        self.interval = max(60, seconds)  # Mínimo de 60 segundos
        if self.verbose:
            logger.info(f"Intervalo de refresh alterado para {self.interval}s")
            
    def _refresh_loop(self) -> None:
        """
        Loop principal de refresh que executa em background.
        """
        # Primeira execução imediata para verificar se a sessão está válida
        self._do_refresh()
        
        while self.running:
            # Espera pelo intervalo configurado
            time.sleep(self.interval)
            
            # Verifica se ainda deve continuar
            if not self.running:
                break
                
            # Tenta fazer o refresh
            self._do_refresh()
    
    def _do_refresh(self) -> bool:
        """
        Executa uma tentativa de refresh com retry em caso de falha.
        
        Returns:
            bool: True se o refresh foi bem-sucedido, False caso contrário
        """
        success = False
        attempts = 0
        
        while not success and attempts < self.max_retries and self.running:
            try:
                if self.verbose and attempts > 0:
                    logger.info(f"Tentativa de refresh {attempts+1}/{self.max_retries}")
                    
                success = self.refresh_callback()
                
                if success:
                    self._last_refresh_time = time.time()
                    self._failed_attempts = 0
                    if self.verbose:
                        logger.info("Refresh de sessão bem-sucedido")
                    return True
                else:
                    attempts += 1
                    self._failed_attempts += 1
                    if self.verbose:
                        logger.warning(f"Falha no refresh de sessão (tentativa {attempts})")
                    
                    # Se ainda temos tentativas, espera antes de tentar novamente
                    if attempts < self.max_retries and self.running:
                        # Backoff exponencial: retry_delay * 2^attempt
                        backoff = self.retry_delay * (2 ** (attempts - 1))
                        if self.verbose:
                            logger.info(f"Aguardando {backoff}s antes da próxima tentativa")
                        time.sleep(backoff)
            
            except Exception as e:
                attempts += 1
                self._failed_attempts += 1
                if self.verbose:
                    logger.error(f"Erro durante refresh de sessão: {e}")
                
                # Se ainda temos tentativas, espera antes de tentar novamente
                if attempts < self.max_retries and self.running:
                    time.sleep(self.retry_delay)
        
        if not success and self.verbose:
            logger.error(f"Refresh de sessão falhou após {attempts} tentativas")
        
        return success
