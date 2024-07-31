import re
import logging

logging.basicConfig(filename='sql_injection_detection.log', level=logging.INFO,format='%(asctime)s - %(message)s')

sql_injection_patterns = {r"(?i)SELECT \* FROM", r"(?i)DROP TABLE", r"(?i)UNION SELECT", r"(?i)--",  # Comentario em SQL
                          r"(?i)OR 1=1",  # Condição OR sempre verdadeira
                          r"(?i)OR '1'='1'",  # Condição OR sempre verdadeira com strings
                          r"(?i);--" }  #Terminação de comando SQL e comentario]

def detect_sql_injection(query):
    #Verifica se uma query contém padrões de injeção de SQL
    for pattern in sql_injection_patterns:
        if re.search(pattern,query):
            return True
        return False
def monitor_queries(log_file_path):
    #Lê um arquivo de log de queries e verifica cada linha para possiveis injeções de SQL.
    with open(log_file_path, 'r') as file:
        for line in file:
            query = line.strip()
            if detect_sql_injection(query):

                logging.info(f'Possivel tentativa de injeçã o de SQL detectada: {query}')

#Exemplo de uso
    log_file_path = 'queries.log' #Arquivo de log de exemplo

    monitor_queries(log_file_path)
