-- ============================================================================
--  Honeypot Analytics - Catalogo inicial de regras de deteccao
--
--  Cada regra e uma LINHA no banco, com sua tecnica MITRE ATT&CK.
--  A query que implementa a regra fica em sql/regras/<codigo>.sql.
--
--  ON CONFLICT DO NOTHING: rodar o seed duas vezes nao quebra nem duplica.
-- ============================================================================

INSERT INTO regra_deteccao (codigo, nome, descricao, mitre_tecnica, severidade) VALUES

('BRUTE_FORCE_SSH',
 'Forca bruta em SSH',
 'Mesmo IP acumula 20 ou mais tentativas de autenticacao malsucedidas em janela de 5 minutos.',
 'T1110.001',
 'media'),

('PASSWORD_SPRAY',
 'Password spraying',
 'Mesmo IP testa a MESMA senha contra 10 ou mais usuarios distintos. Padrao inverso da forca bruta: poucas senhas, muitos usuarios, para escapar de bloqueio por conta.',
 'T1110.003',
 'alta'),

('CREDENCIAL_VALIDA_USADA',
 'Autenticacao bem-sucedida',
 'Sessao autenticou com sucesso. Em honeypot todo login e simulado, portanto qualquer sucesso e sempre evento de interesse maximo.',
 'T1078',
 'critica'),

('DOWNLOAD_ARTEFATO',
 'Download de payload',
 'Sessao executou wget, curl ou tftp buscando arquivo externo - tentativa de trazer malware para o host.',
 'T1105',
 'critica'),

('RECON_SISTEMA',
 'Reconhecimento pos-acesso',
 'Sequencia de comandos de descoberta (uname, whoami, cat /proc/cpuinfo, free, lscpu) nos primeiros segundos da sessao. Bot medindo o que acabou de "invadir".',
 'T1082',
 'baixa'),

('PERSISTENCIA_SSH_KEY',
 'Tentativa de persistencia',
 'Escrita em authorized_keys, crontab ou rc.local - atacante garantindo retorno mesmo apos troca de senha.',
 'T1098.004',
 'critica'),

('DESATIVACAO_DEFESA',
 'Desativacao de defesas',
 'Comandos que param iptables, ufw, SELinux ou matam processos de seguranca.',
 'T1562.001',
 'alta'),

('LIMPEZA_RASTRO',
 'Limpeza de rastros',
 'Remocao ou truncamento de historico e logs (history -c, rm de .bash_history, > /var/log/...).',
 'T1070.003',
 'alta'),

('MINERACAO_CRIPTO',
 'Indicio de cryptomining',
 'Comandos ou downloads associados a mineradores (xmrig, minerd, pool de mineracao na URL).',
 'T1496',
 'alta'),

('REINCIDENTE',
 'Atacante reincidente',
 'IP com 5 ou mais sessoes distintas em 24 horas. Separa varredura oportunista de interesse dirigido no alvo.',
 NULL,
 'media'),

('HORARIO_REGULAR',
 'Cadencia automatizada',
 'IP cujas sessoes se repetem em intervalo estatisticamente regular - assinatura de tarefa agendada, nao de operador humano.',
 NULL,
 'baixa')

ON CONFLICT (codigo) DO NOTHING;
