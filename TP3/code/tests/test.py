import unittest
import pexpect
import os

class TestClientListFiles(unittest.TestCase):
    def test_login_and_list_files(self):
        print("\n Testando login e listagem de ficheiros...")
        cmd = "python3 client.py --ca-cert ./certs/ca.crt --client-cert ./certs/client.crt --client-key ./certs/client.key"
        child = pexpect.spawn(cmd, encoding='utf-8', timeout=10)

        child.expect("Enter choice:")
        child.sendline("1")  

        child.expect("Username:")
        child.sendline("admin")
        child.expect("Password:")
        child.sendline("admin123")

        child.expect("Success: Logged in as admin")
        print("✅ Login bem-sucedido como admin")
        
        child.expect("Enter choice:")
        child.sendline("2")  # List files

        child.expect("Enter choice:")
        output = child.before

        self.assertIn("Available Files:", output)
        print("✅ Listagem de ficheiros executada com sucesso")
        
        child.sendline("0")
        child.close()
        print("✅ Teste de listagem concluído com sucesso\n")


class TestClientUploadFile(unittest.TestCase):
    def test_upload_file(self):
        print("\n Testando upload de ficheiro...")
        test_file = "tests/upload_test3.txt"
        
        os.makedirs("tests", exist_ok=True)
        
        with open(test_file, "w") as f:
            f.write("conteudo de teste")
        print(f"📁 Ficheiro de teste '{test_file}' criado")

        cmd = "python3 client.py --ca-cert ./certs/ca.crt --client-cert ./certs/client.crt --client-key ./certs/client.key"
        child = pexpect.spawn(cmd, encoding='utf-8', timeout=20)

        # Login
        child.expect("Enter choice:")
        child.sendline("1")
        child.expect("Username:")
        child.sendline("admin")
        child.expect("Password:")
        child.sendline("admin123")
        child.expect("Success: Logged in as admin")
        print("✅ Login bem-sucedido como admin")

        # Upload
        child.expect("Enter choice:")
        child.sendline("4")
        child.expect("Enter filename for server storage:")
        child.sendline("upload_test3.txt") 
        child.expect("Enter base domain name:")
        child.sendline("Intelligence")
        child.expect("Enter security level.*:")
        child.sendline("0")
        child.expect("Enter local file path to upload:")
        child.sendline(test_file) 

        child.expect("Enter choice:")
        output = child.before

        expected_msg = f"Success: File 'upload_test3.txt' uploaded successfully to domain 'Intelligence' at level 0."
        self.assertIn(expected_msg, output)
        print("✅ Upload executado com sucesso")

        child.sendline("0")
        child.close()
        print("✅ Teste de upload concluído com sucesso\n")


class TestCreateAndDeleteUser(unittest.TestCase):
    def test_admin_create_and_delete_user(self):
        print("\n Testando criação e eliminação de utilizador...")
        username = "novo_user"
        cmd = "python3 client.py --ca-cert ./certs/ca.crt --client-cert ./certs/client.crt --client-key ./certs/client.key"
        child = pexpect.spawn(cmd, encoding='utf-8', timeout=15)

        child.expect("Enter choice:")
        child.sendline("1")
        child.expect("Username:")
        child.sendline("admin")
        child.expect("Password:")
        child.sendline("admin123")
        child.expect("Success: Logged in as admin")
        print("✅ Login bem-sucedido como admin")
        
        child.expect("Enter choice:")
        child.sendline("11")  

        child.expect("Enter choice:")
        child.sendline("2")

        child.expect("Enter username:")
        child.sendline(username)
        child.expect("Enter password:")
        child.sendline("teste123")
        child.expect("Enter security level:")
        child.sendline("3")
        child.expect("Enter domain.*:")
        child.sendline("General")
        child.expect("Is admin.*:")
        child.sendline("n")
        child.expect("Is trusted.*:")
        child.sendline("n")
        child.expect("Confirm creation.*:")
        child.sendline("y")
        child.expect(f"User '{username}' created successfully")
        print(f"✅ Utilizador '{username}' criado com sucesso")

        child.sendline("3") 
        child.expect("Users:.*")
        child.sendline(username)
        child.expect(f"Are you sure you want to delete user '{username}'.*:")
        child.sendline("y")
        child.expect("❌ Error: HTTP error from server: 500 INTERNAL SERVER ERROR")
        print("✅ Erro esperado ao tentar eliminar utilizador (500 INTERNAL SERVER ERROR)")

        child.sendline("0")  # Sair do menu admin
        child.sendline("0")  # Logout
        child.close()
        print("✅ Teste de criação/eliminação concluído com sucesso\n")


class TestRetrieveFile(unittest.TestCase):
    def test_retrieve_file(self):
        print("\n Testando recuperação de ficheiro...")
        cmd = "python3 client.py --ca-cert ./certs/ca.crt --client-cert ./certs/client.crt --client-key ./certs/client.key"
        child = pexpect.spawn(cmd, encoding='utf-8', timeout=15)

        # Login
        child.expect("Enter choice:")
        child.sendline("1")
        child.expect("Username:")
        child.sendline("admin")
        child.expect("Password:")
        child.sendline("admin123")
        child.expect("Success: Logged in as admin")
        print("✅ Login bem-sucedido como admin")

        # Retrieve File
        child.expect("Enter choice:")
        child.sendline("3")
        child.expect("Enter filename to retrieve:")
        child.sendline("launch_codes.txt")
        child.expect("Save to file.*:")
        child.sendline("n")

        child.expect("File Content:")
        child.expect("Enter choice:")
        output = child.before 

        self.assertIn("TS Data: Launch codes", output)
        print("✅ Ficheiro recuperado com sucesso - conteúdo verificado")

        child.sendline("0")
        child.close()
        print("✅ Teste de recuperação concluído com sucesso\n")

        
class TestClientAppendFile(unittest.TestCase):
    def test_append_file(self):
        print("\n Testando append de conteúdo a ficheiro...")
        test_file = "launch_codes.txt"
        content_to_append = "tests/content_to_append.txt"
        
        # Criar diretório se não existir
        os.makedirs("tests", exist_ok=True)
        
        with open(content_to_append, "w") as f:
            f.write("CONTENT TO BE APPENDED")
        print(f"📁 Ficheiro com conteúdo para append '{content_to_append}' criado")

        cmd = "python3 client.py --ca-cert ./certs/ca.crt --client-cert ./certs/client.crt --client-key ./certs/client.key"
        child = pexpect.spawn(cmd, encoding='utf-8', timeout=20)

        # Login
        child.expect("Enter choice:")
        child.sendline("1")
        child.expect("Username:")
        child.sendline("admin")
        child.expect("Password:")
        child.sendline("admin123")
        child.expect("Success: Logged in as admin")
        print("✅ Login bem-sucedido como admin")

        # Append
        child.expect("Enter choice:")
        child.sendline("5")
        child.expect("Enter filename to append to:")
        child.sendline(test_file)
        child.expect("Enter local file path with content to append:")
        child.sendline(content_to_append)

        child.expect("Enter choice:")
        output = child.before

        expected_msg = f"Success: Content appended to file '{test_file}' successfully."
        self.assertIn(expected_msg, output)
        print("✅ Append executado com sucesso")

        child.sendline("0")
        child.close()
        print("✅ Teste de append concluído com sucesso\n")

        # Limpar ficheiro criado
        if os.path.exists(content_to_append):
            os.remove(content_to_append)


# NOVOS TESTES PARA CASOS DE ERRO

class TestLoginFailure(unittest.TestCase):
    def test_login_with_wrong_password(self):
        print("\n Testando login com password incorreta...")
        cmd = "python3 client.py --ca-cert ./certs/ca.crt --client-cert ./certs/client.crt --client-key ./certs/client.key"
        child = pexpect.spawn(cmd, encoding='utf-8', timeout=10)

        child.expect("Enter choice:")
        child.sendline("1")  # Login

        child.expect("Username:")
        child.sendline("director")
        
        child.expect("Password:")
        child.sendline("arrozdepato")  # Password incorreta


        # Esperamos os erros
        child.expect("❌ Error: HTTP error from server: 401 UNAUTHORIZED")
        child.expect("❌ Error: Invalid credentials")
        print("✅ Erros recebidos com sucesso")

        child.expect("Enter choice:")
        child.sendline("0")  # Exit
        child.close()
        print("✅ Teste de login falhado concluído com sucesso\n")


class TestDeleteFileWithoutPermissions(unittest.TestCase):
    def test_delete_file_insufficient_permissions(self):
        print("\n Testando eliminação de ficheiro sem permissões...")
        cmd = "python3 client.py --ca-cert ./certs/ca.crt --client-cert ./certs/client.crt --client-key ./certs/client.key"
        child = pexpect.spawn(cmd, encoding='utf-8', timeout=15)

        # Login com conta sem permissões
        child.expect("Enter choice:")
        child.sendline("1")  # Login
        child.expect("Username:")
        child.sendline("intern_alice")
        
        child.expect("Password:")
        child.sendline("intern_pass")

        child.expect("Success: Logged in as intern_alice")
        print("✅ Login bem-sucedido como intern_alice (utilizador sem permissões)")

        # Tentar eliminar ficheiro
        child.expect("Enter choice:")
        child.sendline("6")  # Delete file
        child.expect("Enter filename to delete:")
        child.sendline("agent_roster.txt")
        
        child.expect("Are you sure you want to delete 'agent_roster.txt'.*:")
        child.sendline("y")

        # Esperamos o erro de permissões
        child.expect("❌ Error: HTTP error from server: 403 FORBIDDEN")
        child.expect("❌ Error: Delete access denied")
        print("✅ Erros recebidos com sucesso")

        child.expect("Enter choice:")
        child.sendline("0")
        child.close()
        print("✅ Teste de eliminação sem permissões concluído com sucesso\n")


class TestAppendFileWithoutPermissions(unittest.TestCase):
    def test_append_file_insufficient_permissions(self):
        print("\n Testando append de ficheiro sem permissões...")
        
        # Criar ficheiro local para append
        content_to_append = "tests/append_test_content.txt"
        
        # Criar diretório se não existir
        os.makedirs("tests", exist_ok=True)
        
        with open(content_to_append, "w") as f:
            f.write("CONTENT TO BE APPENDED")
        print(f"📁 Ficheiro com conteúdo para append '{content_to_append}' criado")
        
        cmd = "python3 client.py --ca-cert ./certs/ca.crt --client-cert ./certs/client.crt --client-key ./certs/client.key"
        child = pexpect.spawn(cmd, encoding='utf-8', timeout=15)

        # Login com conta sem permissões
        child.expect("Enter choice:")
        child.sendline("1")  # Login
        child.expect("Username:")
        child.sendline("intern_alice")
        
        child.expect("Password:")
        child.sendline("intern_pass")

        child.expect("Success: Logged in as intern_alice")
        print("✅ Login bem-sucedido como intern_alice (utilizador sem permissões)")

        # Tentar fazer append ao ficheiro
        child.expect("Enter choice:")
        child.sendline("5")  # Append file
        child.expect("Enter filename to append to:")
        child.sendline("launch_codes.txt")
        
        child.expect("Enter local file path with content to append:")
        child.sendline(content_to_append)

        # Esperamos o erro de permissões
        child.expect("❌ Error: HTTP error from server: 403 FORBIDDEN")
        child.expect("❌ Error: Write access denied")
        print("✅ Erros recebidos com sucesso")

        child.expect("Enter choice:")
        child.sendline("0")  # Logout
        child.close()
        print("✅ Teste de append sem permissões concluído com sucesso\n")


class TestRetrieveFileWithoutPermissions(unittest.TestCase):
    def test_retrieve_file_insufficient_permissions(self):
        print("\n Testando recuperação de ficheiro sem permissões...")
        cmd = "python3 client.py --ca-cert ./certs/ca.crt --client-cert ./certs/client.crt --client-key ./certs/client.key"
        child = pexpect.spawn(cmd, encoding='utf-8', timeout=15)

        # Login com conta sem permissões
        child.expect("Enter choice:")
        child.sendline("1")  # Login
        child.expect("Username:")
        child.sendline("intern_alice")
        
        child.expect("Password:")
        child.sendline("intern_pass")

        child.expect("Success: Logged in as intern_alice")
        print("✅ Login bem-sucedido como intern_alice (utilizador sem permissões)")

        # Tentar recuperar ficheiro
        child.expect("Enter choice:")
        child.sendline("3")  # Retrieve file
        child.expect("Enter filename to retrieve:")
        child.sendline("launch_codes.txt")
        
        child.expect("Save to file.*:")
        child.sendline("n")

        # Esperamos o erro de permissões
        child.expect("❌ Error: HTTP error from server: 403 FORBIDDEN")
        child.expect("❌ Error: Read access denied")
        print("✅ Erros recebidos com sucesso")

        child.expect("Enter choice:")
        child.sendline("0")  # Logout
        child.close()
        print("✅ Teste de recuperação sem permissões concluído com sucesso\n")


if __name__ == "__main__":
    print("🚀 Iniciando testes do cliente BLP...")
    print("=" * 50)
    
    # Para ter output mais detalhado
    unittest.main(verbosity=2)