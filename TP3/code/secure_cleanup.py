#!/usr/bin/env python3
"""
Módulo de limpeza segura para o cliente BLP.
Implementa mecanismos para eliminar rastros sensíveis após logout.
"""

import os
import sys
import gc
import shutil
import logging
import tempfile
import platform
import subprocess
from typing import List, Optional, Set

# Configuração de logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SecureCleanup')

class SecureCleanup:
    """
    Classe responsável por limpar rastros sensíveis após logout.
    Inclui limpeza de memória, ficheiros temporários e histórico.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Inicializa o gestor de limpeza segura.
        
        Args:
            verbose: Se True, imprime mensagens de debug
        """
        self.verbose = verbose
        self.downloaded_files: Set[str] = set()
        self.temp_files: Set[str] = set()
        self.temp_dirs: Set[str] = set()
        
    def register_downloaded_file(self, filepath: str) -> None:
        """
        Regista um ficheiro descarregado para posterior limpeza.
        
        Args:
            filepath: Caminho absoluto do ficheiro
        """
        if os.path.exists(filepath):
            self.downloaded_files.add(os.path.abspath(filepath))
            if self.verbose:
                logger.info(f"Ficheiro registado para limpeza: {filepath}")
                
    def register_temp_file(self, filepath: str) -> None:
        """
        Regista um ficheiro temporário para posterior limpeza.
        
        Args:
            filepath: Caminho absoluto do ficheiro
        """
        if os.path.exists(filepath):
            self.temp_files.add(os.path.abspath(filepath))
            if self.verbose:
                logger.info(f"Ficheiro temporário registado: {filepath}")
                
    def register_temp_dir(self, dirpath: str) -> None:
        """
        Regista um diretório temporário para posterior limpeza.
        
        Args:
            dirpath: Caminho absoluto do diretório
        """
        if os.path.exists(dirpath) and os.path.isdir(dirpath):
            self.temp_dirs.add(os.path.abspath(dirpath))
            if self.verbose:
                logger.info(f"Diretório temporário registado: {dirpath}")
    
    def create_temp_file(self, prefix: str = "blp_", suffix: str = "") -> str:
        """
        Cria um ficheiro temporário e regista-o para limpeza.
        
        Args:
            prefix: Prefixo para o nome do ficheiro
            suffix: Sufixo para o nome do ficheiro
            
        Returns:
            str: Caminho do ficheiro temporário
        """
        fd, filepath = tempfile.mkstemp(prefix=prefix, suffix=suffix)
        os.close(fd)
        self.register_temp_file(filepath)
        return filepath
        
    def create_temp_dir(self, prefix: str = "blp_") -> str:
        """
        Cria um diretório temporário e regista-o para limpeza.
        
        Args:
            prefix: Prefixo para o nome do diretório
            
        Returns:
            str: Caminho do diretório temporário
        """
        dirpath = tempfile.mkdtemp(prefix=prefix)
        self.register_temp_dir(dirpath)
        return dirpath
    
    def secure_clear_bytes(self, byte_array: bytearray) -> None:
        """
        Sobrescreve um array de bytes com zeros.
        
        Args:
            byte_array: Array de bytes a limpar
        """
        if byte_array:
            byte_len = len(byte_array)
            for i in range(byte_len):
                byte_array[i] = 0
            if self.verbose:
                logger.info(f"Array de bytes limpo ({byte_len} bytes)")
                
    def secure_delete_file(self, filepath: str) -> bool:
        """
        Elimina um ficheiro de forma segura, sobrescrevendo o conteúdo.
        
        Args:
            filepath: Caminho do ficheiro a eliminar
            
        Returns:
            bool: True se eliminado com sucesso, False caso contrário
        """
        if not os.path.exists(filepath) or os.path.isdir(filepath):
            return False
            
        try:
            # Obter tamanho do ficheiro
            file_size = os.path.getsize(filepath)
            
            # Sobrescrever com zeros
            with open(filepath, 'wb') as f:
                # Escrever em blocos para ficheiros grandes
                block_size = min(1024 * 1024, file_size)  # 1MB ou tamanho do ficheiro
                for _ in range(0, file_size, block_size):
                    f.write(b'\x00' * min(block_size, file_size - f.tell()))
                    
            # Eliminar ficheiro
            os.remove(filepath)
            
            if self.verbose:
                logger.info(f"Ficheiro eliminado de forma segura: {filepath}")
            return True
            
        except Exception as e:
            if self.verbose:
                logger.error(f"Erro ao eliminar ficheiro {filepath}: {e}")
            return False
            
    def clear_terminal_history(self) -> bool:
        """
        Tenta limpar o histórico do terminal.
        
        Returns:
            bool: True se limpo com sucesso, False caso contrário
        """
        try:
            system = platform.system().lower()
            
            if system == 'linux' or system == 'darwin':
                # Limpar histórico em sistemas Unix-like
                histfile = os.path.expanduser("~/.bash_history")
                if os.path.exists(histfile):
                    with open(histfile, 'w') as f:
                        pass
                
                # Tentar limpar histórico do terminal atual
                subprocess.call(['history', '-c'], shell=True)
                
            elif system == 'windows':
                # Limpar histórico em Windows (PowerShell)
                subprocess.call(['powershell', '-Command', 'Clear-History'], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL)
                
            if self.verbose:
                logger.info("Histórico do terminal limpo")
            return True
            
        except Exception as e:
            if self.verbose:
                logger.error(f"Erro ao limpar histórico do terminal: {e}")
            return False
            
    def clear_screen(self) -> None:
        """
        Limpa o ecrã do terminal.
        """
        system = platform.system().lower()
        
        if system == 'windows':
            os.system('cls')
        else:
            os.system('clear')
            
    def cleanup_all_temp_files(self) -> None:
        """
        Elimina todos os ficheiros temporários registados.
        """
        # Limpar ficheiros temporários
        for filepath in self.temp_files.copy():
            if os.path.exists(filepath):
                try:
                    self.secure_delete_file(filepath)
                    self.temp_files.remove(filepath)
                except Exception as e:
                    if self.verbose:
                        logger.error(f"Erro ao eliminar ficheiro temporário {filepath}: {e}")
        
        # Limpar diretórios temporários
        for dirpath in self.temp_dirs.copy():
            if os.path.exists(dirpath) and os.path.isdir(dirpath):
                try:
                    shutil.rmtree(dirpath)
                    self.temp_dirs.remove(dirpath)
                    if self.verbose:
                        logger.info(f"Diretório temporário eliminado: {dirpath}")
                except Exception as e:
                    if self.verbose:
                        logger.error(f"Erro ao eliminar diretório temporário {dirpath}: {e}")
                        
    def cleanup_downloaded_files(self, ask_confirmation: bool = True) -> None:
        """
        Elimina todos os ficheiros descarregados registados.
        
        Args:
            ask_confirmation: Se True, pede confirmação antes de eliminar
        """
        if not self.downloaded_files:
            return
            
        if ask_confirmation:
            print("\nFicheiros descarregados durante a sessão:")
            for filepath in sorted(self.downloaded_files):
                print(f"  - {filepath}")
                
            response = input("\nEliminar estes ficheiros? (s/n): ").strip().lower()
            if response != 's':
                print("Ficheiros mantidos.")
                return
        
        for filepath in self.downloaded_files.copy():
            if os.path.exists(filepath):
                try:
                    self.secure_delete_file(filepath)
                    self.downloaded_files.remove(filepath)
                except Exception as e:
                    if self.verbose:
                        logger.error(f"Erro ao eliminar ficheiro descarregado {filepath}: {e}")
    
    def secure_logout_cleanup(self, 
                             clear_memory: bool = True,
                             clear_downloads: bool = True,
                             clear_temp: bool = True,
                             clear_history: bool = True,
                             clear_terminal: bool = True) -> None:
        """
        Executa limpeza completa após logout.
        
        Args:
            clear_memory: Se True, força garbage collection
            clear_downloads: Se True, elimina ficheiros descarregados
            clear_temp: Se True, elimina ficheiros temporários
            clear_history: Se True, limpa histórico do terminal
            clear_terminal: Se True, limpa o ecrã do terminal
        """
        if self.verbose:
            logger.info("Iniciando limpeza de segurança após logout")
            
        # Limpar ficheiros temporários
        if clear_temp:
            self.cleanup_all_temp_files()
            
        # Limpar ficheiros descarregados
        if clear_downloads:
            self.cleanup_downloaded_files(ask_confirmation=False)
            
        # Limpar histórico do terminal
        if clear_history:
            self.clear_terminal_history()
            
        # Forçar garbage collection para limpar memória
        if clear_memory:
            gc.collect()
            if self.verbose:
                logger.info("Garbage collection forçado")
                
        # Limpar ecrã do terminal
        if clear_terminal:
            self.clear_screen()
            
        if self.verbose:
            logger.info("Limpeza de segurança concluída")
            
    def secure_clear_object(self, obj: object) -> None:
        """
        Tenta limpar um objeto de forma segura.
        
        Args:
            obj: Objeto a limpar
        """
        if obj is None:
            return
            
        # Limpar strings
        if isinstance(obj, str):
            # Não podemos modificar strings diretamente em Python
            # pois são imutáveis, mas podemos forçar sua remoção
            obj = None
            return
            
        # Limpar bytes e bytearrays
        if isinstance(obj, bytearray):
            self.secure_clear_bytes(obj)
            return
            
        # Limpar dicionários
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                self.secure_clear_object(obj[key])
                obj[key] = None
            obj.clear()
            return
            
        # Limpar listas
        if isinstance(obj, list):
            for i in range(len(obj)):
                self.secure_clear_object(obj[i])
                obj[i] = None
            obj.clear()
            return
