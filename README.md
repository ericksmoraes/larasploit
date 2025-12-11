# larasploit
Laravel Automated Vulnerability Scanner

Ferramenta automatizada para detecção de vulnerabilidades em aplicações Laravel, incluindo scanner de configurações expostas e exploração de CVE-2021-3129.

✨ Características

🎯 Fingerprinting Automático: Detecta versões de Laravel, PHP e servidor web
🔐 Detecção de .env Exposto: Identifica arquivos de configuração expostos
🐛 Debug Mode Detection: Verifica se a aplicação está em modo debug
💥 CVE-2021-3129: Detecta vulnerabilidade Ignition RCE
📊 Análise de Cookies: Identifica cookies Laravel (XSRF-TOKEN, sessions)
🚀 Modo Interativo: Shell interativo para exploração (requer dependências)
🎨 Output Colorido: Interface amigável com cores no terminal

🚀 Instalação
Instalação Básica (Modo Detecção)
bash# Clone o repositório
git clone https://github.com/seu-usuario/larasploit.git
cd larasploit

# Crie um ambiente virtual (recomendado)
python3 -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate

# Instale as dependências
pip3 install -r requirements.txt
Instalação Completa (Modo Exploração)
bash# Instale as dependências básicas primeiro
pip3 install -r requirements.txt

# Clone phpggc para geração de payloads
git clone https://github.com/ambionics/phpggc.git

# Clone o módulo ignition_rce (opcional, para exploração)
git clone https://github.com/OWASP/Larasploit.git temp_larasploit
cp -r temp_larasploit/ignition_rce ./
rm -rf temp_larasploit
Dependências Python
Crie um arquivo requirements.txt com:
requests>=2.31.0
beautifulsoup4>=4.12.0
urllib3>=2.0.0
💻 Uso
Modo Básico (Detecção)
bash# Scan simples
python3 laravel.py https://target.com

# Com ambiente virtual ativado
source venv/bin/activate
python3 laravel.py https://example.com
Modo Interativo (Exploração)
bash# Requer phpggc e ignition_rce instalados
python3 laravel.py https://target.com -i
Exemplos de Saída
 [Target]:  https://example.com
 
 [~] Application Fingerprint

 [HTTP STATUS]:  200
 [Server]:  nginx/1.22.1
 [PHP Version]:  PHP/7.3.33
 [Common Laravel Cookie]:  XSRF-TOKEN: eyJpdiI6InRuNFBDUElz...
 [Common Laravel Cookie]:  laravel_session: eyJpdiI6ImNNRUFEcnJ0...
 [INFO]:  Laravel 8 detected (with ignition)!
🎯 Vulnerabilidades Detectadas
1. Arquivo .env Exposto

Severidade: 🔴 Crítica
Impacto: Vazamento de credenciais, API keys, secrets
Detecção: Verifica acesso a /.env

2. CVE-2021-3129 (Ignition RCE)

Severidade: 🔴 Crítica
Versões Afetadas: Laravel 8.x com Ignition <= 2.5.1
Impacto: Execução remota de código
Detecção: Testa endpoint /_ignition/execute-solution

3. Debug Mode Habilitado

Severidade: 🟡 Média
Impacto: Vazamento de informações, stack traces
Detecção: Testa múltiplos métodos HTTP

4. Instalação Laravel Padrão

Severidade: 🟢 Baixa
Impacto: Fingerprinting facilitado
Detecção: Analisa página inicial e estrutura HTML

📖 Exemplos
Exemplo 1: Site Vulnerável
bash$ python3 laravel.py https://vulnerable-site.com

 [VULN] Vulnerability detected: .env file exposed
 [INFO]: APP_KEY leaked: base64:xxxxxxxxxxx
 [VULN] Vulnerability detected: Remote Code Execution with CVE-2021-3129
Exemplo 2: Site Seguro
bash$ python3 laravel.py https://secure-site.com

 [HTTP STATUS]:  200
 [Server]:  nginx/1.22.1
 [PHP Version]:  PHP/8.2.0
 [Common Laravel Cookie]:  XSRF-TOKEN: ...
Exemplo 3: Modo Interativo
bash$ python3 laravel.py https://target.com -i

 [!] Larasploit Interactive session [ON]
 [iCMD]$ whoami
www-data

 [iCMD]$ ls -la
total 48
drwxr-xr-x 12 www-data www-data 4096 Dec 11 10:30 .
...

 [iCMD]$ exit
🛠️ Requisitos
Software

Python 3.8+
PHP 7.x+ (para geração de payloads com phpggc)
Git

Bibliotecas Python

requests
beautifulsoup4
urllib3

Ferramentas Opcionais

phpggc: Geração de gadget chains PHP
ignition_rce: Módulo de exploração do Ignition

⚠️ Aviso Legal
IMPORTANTE: Esta ferramenta foi desenvolvida apenas para fins educacionais e testes de segurança autorizados.
