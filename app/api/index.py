import os
from datetime import datetime, time, timedelta, date
from functools import wraps
import jwt
from flask import Flask, jsonify, request
import psycopg2
from werkzeug.security import check_password_hash


NOT_FOUND_CODE = 401
OK_CODE = 200
SUCCESS_CODE = 201
NO_CONTENT_CODE = 204
BAD_REQUEST_CODE = 400
UNAUTHORIZED_CODE = 401
FORBIDDEN_CODE = 403
NOT_FOUND = 404
SERVER_ERROR = 500

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'mysecretkey')

def get_connection():
    conn = psycopg2.connect("host=aid.estgoh.ipc.pt dbname=db2022147162 user=a2022147162 password=guibastos")
    return conn



# Endpoints utilizando a estrutura de tabelas já existente
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = jwt.encode({'password': data['password']}, app.config['SECRET_KEY'], algorithm='HS256')
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO utilizador (username, password) VALUES (%s, %s) RETURNING id",
                    (data['username'], hashed_password)
                )
                user_id = cursor.fetchone()[0]
                conn.commit()
                return jsonify({"message": "Utilizador registado com sucesso.", "user_id": user_id}), SUCCESS_CODE
    except psycopg2.IntegrityError:
        return jsonify({"message": "Nome de utilizador já existe."}), BAD_REQUEST_CODE
    except Exception as e:
        return jsonify({"message": "Erro ao registrar utilizador.", "error": str(e)}), SERVER_ERROR



@app.route('/login', methods=['POST'])
def login():
    data = request.json
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, password FROM utilizador WHERE username = %s",
                    (data['username'],)
                )
                user = cursor.fetchone()
                if user and jwt.decode(user[1], app.config['SECRET_KEY'], algorithms=['HS256'])['password'] == data['password']:
                    token = jwt.encode({
                        'user_id': user[0], 
                        'exp': datetime.utcnow() + timedelta(minutes=5)  
                    }, app.config['SECRET_KEY'], algorithm='HS256')

                    return jsonify({"token": token, "user_id": user[0]}), OK_CODE
                return jsonify({"message": "Credenciais inválidas."}), UNAUTHORIZED_CODE
    except Exception as e:
        return jsonify({"message": "Erro ao autenticar usuário.", "error": str(e)}), SERVER_ERROR



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization').split(" ")[1]
        try:
            # Decodificar o token e verificar a validade
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            # Se o token não estiver expirado, ele é válido
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expirado."}), UNAUTHORIZED_CODE
        except Exception as e:
            return jsonify({"message": "Erro de autenticação.", "error": str(e)}), UNAUTHORIZED_CODE
    return decorated



@app.route('/logout', methods=['POST'])
@token_required
def logout():
    # Não há necessidade de remover tokens, pois estamos usando a expiração do próprio JWT
    return jsonify({"message": "Logout realizado com sucesso."}), OK_CODE




@app.route('/utilizador/<int:user_id>', methods=['GET'])
@token_required
def get_user_(user_id):
    authorization_header = request.headers.get('Authorization')

    if not authorization_header:
        return jsonify({"message": "Cabeçalho 'Authorization' ausente."}), BAD_REQUEST_CODE

    try:
        token = authorization_header.split(" ")[1]
    except IndexError:
        return jsonify({"message": "Formato do cabeçalho 'Authorization' inválido. Esperado 'Bearer <token>'."}), BAD_REQUEST_CODE

    try:
        # Decodificando o token JWT
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user_id = decoded_token['user_id']  # Obtém o ID do usuário a partir do token

        # Verificando se o ID do usuário no token corresponde ao ID da URL (ou se é admin)
        if current_user_id != user_id:
            return jsonify({"message": "Acesso negado. Não tem permissão para visualizar este perfil."}), FORBIDDEN_CODE

        # Consultando o banco de dados para pegar as informações do usuário
        with get_connection() as conn:
            with conn.cursor() as cursor:
                # Contando o número de eventos criados pelo usuário (tabela 'evento')
                cursor.execute("SELECT COUNT(*) FROM eventos WHERE id_utilizador = %s", (user_id,))
                eventos_criados = cursor.fetchone()[0]

                # Contando o número de eventos inscritos pelo usuário (tabela 'inscricao')
                cursor.execute("SELECT COUNT(*) FROM inscricao WHERE id_utilizador = %s", (user_id,))
                eventos_inscritos = cursor.fetchone()[0]

                # Pegando os detalhes do usuário (nome e e-mail da tabela 'utilizador')
                cursor.execute("SELECT username FROM utilizador WHERE id = %s", (user_id,))
                result = cursor.fetchone()

                if result:
                    nome = result[0]
                else:
                    return jsonify({"message": "Utilizador não encontrado."}), NOT_FOUND

                # Preparando os dados do perfil
                user_data = {
                    "username": nome,
                    "eventosCriados": eventos_criados,
                    "eventosInscritos": eventos_inscritos
                }

                return jsonify(user_data), OK_CODE

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado."}), UNAUTHORIZED_CODE
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido."}), UNAUTHORIZED_CODE
    except Exception as e:
        return jsonify({"message": "Erro ao procurar o utilizador.", "error": str(e)}), SERVER_ERROR


@app.route('/events/add', methods=['POST'])
@token_required
def create_event():
    authorization_header = request.headers.get('Authorization')

    if not authorization_header:
        return jsonify({"message": "Cabeçalho 'Authorization' ausente."}), BAD_REQUEST_CODE

    try:
        token = authorization_header.split(" ")[1]
    except IndexError:
        return jsonify({"message": "Formato do cabeçalho 'Authorization' inválido. Esperado 'Bearer <token>'."}), BAD_REQUEST_CODE

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']

        # Recebe os dados do evento do corpo da requisição
        event_data = request.get_json()
        print(event_data)

        tipo = event_data.get('tipo')
        descricao = event_data.get('descricao')
        local = event_data.get('local')
        data_evento = event_data.get('dataEvento')
        hora_evento = event_data.get('horaEvento')
        data_limite = event_data.get('dataLimite')
        hora_limite = event_data.get('horaLimite')
        numero_lugares = event_data.get('numeroLugares')
        preco = event_data.get('preco')
        gratuito = event_data.get('gratuito')

        # Verificar se data_evento ou data_limite são válidos
        try:
            datetime_evento = datetime.strptime(data_evento, "%Y-%m-%d %H:%M:%S")
            datetime_limite = datetime.strptime(data_limite, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return jsonify({"message": "Formato de data ou hora inválido. Use 'YYYY-MM-DD HH:MM:SS'."}), BAD_REQUEST_CODE

        agora = datetime.now()

        # Verificar se as datas são válidas
        if datetime_evento < agora:
            return jsonify({"message": "A data do evento não pode ser anterior à data atual."}), BAD_REQUEST_CODE
        if datetime_limite < agora:
            return jsonify({"message": "A data limite de inscrição não pode ser anterior à data atual."}), BAD_REQUEST_CODE
        if datetime_limite >= datetime_evento:
            return jsonify({"message": "A data limite de inscrição deve ser anterior à data do evento."}), BAD_REQUEST_CODE

        # Geração do novo evento sem o id e id_utilizador
        with get_connection() as conn:
            with conn.cursor() as cursor:
                # Insere o evento sem id (auto incremento do banco) e associando o id_utilizador do token
                cursor.execute("""
                    INSERT INTO eventos (tipo, descricao, local, data_evento, hora_evento, data_limite, hora_limite, numero_lugares, preco, gratuito, id_utilizador)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (tipo, descricao, local, data_evento, hora_evento, data_limite, hora_limite, numero_lugares, preco, gratuito, user_id))
                conn.commit()

                return jsonify({"message": "Evento criado com sucesso!"}), OK_CODE

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado."}), UNAUTHORIZED_CODE
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido."}), UNAUTHORIZED_CODE
    except Exception as e:
        print(f"Erro ao inserir evento: {str(e)}")  # Log detalhado do erro
        return jsonify({"message": "Erro ao criar evento.", "error": str(e)}), SERVER_ERROR


@app.route('/events/edit', methods=['PUT'])
@token_required
def edit_event():
    data = request.json 
    app.logger.info(f"Dados recebidos no corpo: {data}")
    # Dados do corpo da requisição (contendo os campos a serem alterados)
    eventoId = data.get('id')  # O ID do evento será passado no corpo da requisição JSON
    token = request.headers.get('Authorization').split(" ")[1]
    
    if not eventoId :
        return jsonify({"message": "ID do evento não fornecido."}), BAD_REQUEST_CODE
    
    try:
        # Decodificar o token para obter o user_id
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']
        
        # Verificar se o evento existe e se o utilizador é o criador do evento
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id_utilizador FROM eventos WHERE id = %s", (eventoId,))
                event = cursor.fetchone()
                if not event:
                    return jsonify({"message": "Evento não encontrado."}), NOT_FOUND
                if event[0] != user_id:
                    return jsonify({"message": "Você não tem permissão para editar este evento."}), FORBIDDEN_CODE
                
                # Atualizar apenas os campos fornecidos
                set_clauses = []
                params = []
                
                if 'tipo' in data:
                    set_clauses.append("tipo = %s")
                    params.append(data['tipo'])
                if 'descricao' in data:
                    set_clauses.append("descricao = %s")
                    params.append(data['descricao'])
                if 'local' in data:
                    set_clauses.append("local = %s")
                    params.append(data['local'])
                if 'dataEvento' in data:
                    set_clauses.append("data_evento = %s")
                    params.append(data['dataEvento'])
                if 'horaEvento' in data:
                    set_clauses.append("hora_evento = %s")
                    params.append(data['horaEvento'])
                if 'dataLimite' in data:
                    set_clauses.append("data_limite = %s")
                    params.append(data['dataLimite'])
                if 'horaLimite' in data:
                    set_clauses.append("hora_limite = %s")
                    params.append(data['horaLimite'])
                if 'numeroLugares' in data:
                    set_clauses.append("numero_lugares = %s")
                    params.append(data['numeroLugares'])
                if 'preco' in data:
                    set_clauses.append("preco = %s")
                    params.append(float(data['preco']))
                if 'gratuito' in data:
                    set_clauses.append("gratuito = %s")
                    params.append(data['gratuito'])

                if not set_clauses:
                    return jsonify({"message": "Nenhum dado para atualização foi fornecido."}), BAD_REQUEST_CODE

                # Adicionar o ID do evento como o último parâmetro
                params.append(eventoId)
                
                # Gerar a string para a cláusula SET com os campos atualizados
                set_clause = ", ".join(set_clauses)
                
                # Executar a atualização no banco de dados
                cursor.execute(f"""
                    UPDATE eventos 
                    SET {set_clause}
                    WHERE id = %s
                """, tuple(params))
                conn.commit()
                
                return jsonify({"message": "Evento atualizado com sucesso."}), OK_CODE
    except Exception as e:
        return jsonify({"message": "Erro ao editar evento.", "error": str(e)}), SERVER_ERROR


@app.route('/events/<int:event_id>', methods=['GET'])
@token_required
def get_event_by_id(event_id):
    authorization_header = request.headers.get('Authorization')

    if not authorization_header:
        return jsonify({"message": "Cabeçalho 'Authorization' ausente."}), BAD_REQUEST_CODE

    try:
        token = authorization_header.split(" ")[1]
    except IndexError:
        return jsonify({"message": "Formato do cabeçalho 'Authorization' inválido. Esperado 'Bearer <token>'."}), BAD_REQUEST_CODE

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']

        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM eventos WHERE id = %s", (event_id,))
                event = cursor.fetchone()

                if not event:
                    return jsonify({"message": "Evento não encontrado."}), NOT_FOUND

                def convert_to_datetime(date_time_str):
                    if date_time_str:
                        try:
                            date_time_obj = datetime.strptime(date_time_str, "%Y-%m-%d %H:%M:%S")
                            data_evento = date_time_obj.strftime("%Y-%m-%d")
                            hora_evento = date_time_obj.strftime("%H:%M")
                            return data_evento, hora_evento
                        except ValueError as e:
                            print(f"Erro ao converter '{date_time_str}': {e}")
                            return None, None
                    return None, None

                dataEvento, horaEvento = convert_to_datetime(event[5])
                dataLimite, horaLimite = convert_to_datetime(event[7])

                dados_evento = {
                    'id': event[0],
                    'tipo': event[2],
                    'descricao': event[3],
                    'local': event[4],
                    'dataEvento': dataEvento,
                    'horaEvento': horaEvento,
                    'dataLimite': dataLimite,
                    'horaLimite': horaLimite,
                    'numeroLugares': event[9],
                    'preco': event[10],
                    'gratuito': event[11]
                }
                return jsonify(dados_evento), OK_CODE

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expirado."}), UNAUTHORIZED_CODE
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido."}), UNAUTHORIZED_CODE
    except Exception as e:
        return jsonify({"message": "Erro ao buscar evento.", "error": str(e)}), SERVER_ERROR



@app.route('/events/remover/<int:event_id>', methods=['DELETE'])
@token_required
def delete_event(event_id):  # Agora o event_id é passado diretamente pela URL
    token = request.headers.get('Authorization').split(" ")[1]
    
    try:
        # Decodificar o token para obter o user_id
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']
        
        # Verificar se o evento existe e se o usuário é o criador do evento
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id_utilizador FROM eventos WHERE id = %s", (event_id,))
                event = cursor.fetchone()
                if not event:
                    return jsonify({"message": "Evento não encontrado."}), NOT_FOUND
                if event[0] != user_id:
                    return jsonify({"message": "Você não tem permissão para remover este evento."}), FORBIDDEN_CODE
                
                # Remover o evento
                cursor.execute("DELETE FROM eventos WHERE id = %s", (event_id,))
                conn.commit()
                
                return jsonify({"message": "Evento removido com sucesso."}), OK_CODE
    except Exception as e:
        return jsonify({"message": "Erro ao remover evento.", "error": str(e)}), SERVER_ERROR
    




@app.route('/events/inscrever', methods=['POST'])
@token_required
def inscrever_evento():
    data = request.json  # Dados do corpo da requisição (contendo o ID do evento)
    token = request.headers.get('Authorization').split(" ")[1]

    event_id = data.get('event_id')
    if not event_id:
        return jsonify({"message": "ID do evento não fornecido."}), BAD_REQUEST_CODE

    try:
        # Decodificar o token para obter o user_id
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']

        with get_connection() as conn:
            with conn.cursor() as cursor:
                # Iniciar uma transação e bloqueio do evento
                #cursor.execute("BEGIN TRANSACTION;")

                # Verificar se o evento existe
                cursor.execute("SELECT id, data_evento, data_limite, numero_lugares FROM eventos WHERE id = %s", (event_id,))
                event = cursor.fetchone()
                if not event:
                    return jsonify({"message": "Evento não encontrado."}), NOT_FOUND

                data_evento = datetime.strptime(event[1], "%Y-%m-%d %H:%M:%S")
                data_limite = datetime.strptime(event[2], "%Y-%m-%d %H:%M:%S")
                available_seats = event[3]

                if data_limite < datetime.today():
                    return jsonify({"message": "O prazo de inscrição já passou."}), BAD_REQUEST_CODE

                if available_seats < 0:
                    return jsonify({"message": "Não há lugares disponíveis para este evento."}), BAD_REQUEST_CODE
                
                data_hora_inscricao = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Verificar se o usuário está inscrito
                cursor.execute(""" 
                    SELECT id, estado FROM inscricao WHERE id_utilizador = %s AND id_evento = %s
                """, (user_id, event_id))
                existing_subscription = cursor.fetchone()

                if existing_subscription:
                    if not existing_subscription[1]:  # Se `estado` é `FALSE` (cancelado)
                        cursor.execute("""
                            UPDATE inscricao
                            SET estado = TRUE, data_hora_inscricao = %s
                            WHERE id = %s
                        """, (data_hora_inscricao, existing_subscription[0]))
                        cursor.execute("""
                            UPDATE eventos SET numero_lugares = numero_lugares - 1 WHERE id = %s
                        """, (event_id,))
                    else:
                        return jsonify({"message": "Você já está inscrito neste evento."}), BAD_REQUEST_CODE
                else:
                    # INCLUIR data_hora_inscricao na query de inserção
                    cursor.execute("""
                        INSERT INTO inscricao (id_utilizador, id_evento, estado, data_hora_inscricao) 
                        VALUES (%s, %s, TRUE, %s) RETURNING id
                    """, (user_id, event_id, data_hora_inscricao))
                    subscription_id = cursor.fetchone()[0]

                    cursor.execute("""
                        UPDATE eventos SET numero_lugares = numero_lugares - 1 WHERE id = %s
                    """, (event_id,))
                
                conn.commit()
                return jsonify({"message": "Inscrição realizada com sucesso."}), SUCCESS_CODE

    except Exception as e:
        print(e)
        return jsonify({"message": "Erro ao realizar inscrição.", "error": str(e)}), SERVER_ERROR





@app.route('/events/cancelar', methods=['POST'])
@token_required
def cancelar_inscricao():
    data = request.json  # Dados do corpo da requisição (contendo o ID do evento)
    token = request.headers.get('Authorization').split(" ")[1]

    event_id = data.get('event_id')
    if not event_id:
        return jsonify({"message": "ID do evento não fornecido."}), BAD_REQUEST_CODE

    try:
        # Decodificar o token para obter o user_id
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']

        with get_connection() as conn:
            with conn.cursor() as cursor:
                # Verificar se o evento existe
                cursor.execute("SELECT id FROM eventos WHERE id = %s", (event_id,))
                event = cursor.fetchone()
                if not event:
                    return jsonify({"message": "Evento não encontrado."}), NOT_FOUND

                # Verificar se o usuário está inscrito
                cursor.execute(""" 
                    SELECT id, estado FROM inscricao WHERE id_utilizador = %s AND id_evento = %s
                """, (user_id, event_id))
                existing_subscription = cursor.fetchone()

                if existing_subscription:
                    if existing_subscription[1]:  # Se `estado` é `TRUE` (inscrito)
                        cursor.execute("""
                            UPDATE inscricao
                            SET estado = FALSE
                            WHERE id = %s
                        """, (existing_subscription[0],))
                        cursor.execute("""
                            UPDATE eventos SET numero_lugares = numero_lugares + 1 WHERE id = %s
                        """, (event_id,))
                    else:
                        return jsonify({"message": "Sua inscrição já foi cancelada."}), BAD_REQUEST_CODE
                else:
                    return jsonify({"message": "Você não está inscrito neste evento."}), BAD_REQUEST_CODE
                
                conn.commit()
                return jsonify({"message": "Inscrição cancelada com sucesso."}), SUCCESS_CODE

    except Exception as e:
        return jsonify({"message": "Erro ao cancelar inscrição.", "error": str(e)}), SERVER_ERROR






@app.route('/list', methods=['GET'])
@token_required
def list_events():
    try:
        # Obter o token do header de autorização
        token = request.headers.get('Authorization').split(" ")[1]

        # Decodificar o token para obter o user_id
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']

        tipo_evento = request.args.get('tipo')

        with get_connection() as conn:
            with conn.cursor() as cursor:
                # Consulta para buscar todos os eventos
                query = """
                    SELECT id, tipo, descricao, local, data_evento, hora_evento, data_limite, hora_limite, numero_lugares, preco, gratuito, id_utilizador
                    FROM eventos
                    WHERE 1=1
                """
                params = []

                # Filtro por tipo de evento
                if tipo_evento:
                    query += " AND tipo = %s"
                    params.append(tipo_evento)

                # Executar a consulta com os parâmetros
                cursor.execute(query, params)
                events = cursor.fetchall()

                # Se não houver eventos, retornar uma lista vazia
                if not events:
                    return jsonify([]), 200

                def convert_to_datetime(date_time_str):
                    # Converter a data e hora
                    if date_time_str:
                        try:
                            # Usando o formato correto que inclui data e hora
                            date_time_obj = datetime.strptime(date_time_str, "%Y-%m-%d %H:%M:%S")
                            # Formatando a data como YYYY:MM:DD
                            data_evento = date_time_obj.strftime("%Y-%m-%d")
                            # Formatando a hora como HH:mm:ss
                            hora_evento = date_time_obj.strftime("%H:%M")
                            
                            return data_evento, hora_evento  # Retorna como strings formatadas
                        except ValueError as e:
                            print(f"Erro ao converter '{date_time_str}': {e}")
                            return None, None
                    return None, None

                # Estruturar os dados para retornar ao cliente
                events_list = []
                for event in events:
                    # Chamando a função de conversão para cada evento
                    data_evento, hora_evento = convert_to_datetime(event[4])  # Evento data e hora
                    data_limite, hora_limite = convert_to_datetime(event[6])  # Limite data e hora

                    # Verificar se o utilizador está inscrito no evento
                    inscrito = False
                    if user_id:
                        # Consulta para verificar o estado da inscrição do utilizador
                        cursor.execute("""
                            SELECT estado FROM inscricao
                            WHERE id_utilizador = %s AND id_evento = %s
                        """, (user_id, event[0]))

                        result = cursor.fetchone()
                        if result and result[0] == 1:  # Caso o estado seja 1 (inscrito)
                            inscrito = True

                    # Adicionar evento à lista com o campo 'inscrito'
                    events_list.append({
                        "id": event[0],
                        "tipo": event[1],
                        "descricao": event[2],
                        "local": event[3],
                        "dataEvento": data_evento,  # Agora como string no formato YYYY:MM:DD
                        "horaEvento": hora_evento,  # Agora como string no formato HH:mm:ss
                        "dataLimite": data_limite,  # Agora como string no formato YYYY:MM:DD
                        "horaLimite": hora_limite,  # Agora como string no formato HH:mm:ss
                        "numeroLugares": event[8],
                        "preco": event[9],  # Já como número ou string formatada
                        "gratuito": event[10],
                        "id_utilizador": event[11],
                        "inscrito": inscrito  # Adicionando o campo 'inscrito' à resposta
                    })

                return jsonify(events_list), 200

    except Exception as e:
        return jsonify({"message": "Erro ao listar eventos.", "error": str(e)}), 500




@app.route('/events/<int:event_id>/inscritos', methods=['GET'])
@token_required
def get_inscritos(event_id):
    try:
        token = request.headers.get('Authorization').split(" ")[1]
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']

        with get_connection() as conn:
            with conn.cursor() as cursor:
                query = "SELECT id_utilizador FROM eventos WHERE id = %s"
                cursor.execute(query, (event_id,))
                evento = cursor.fetchone()

                if evento is None:
                    return jsonify({"message": "Evento não encontrado."}), NOT_FOUND
                
                criador_evento_id = evento[0]

                # Verifique se o usuário autenticado é o criador do evento
                if criador_evento_id != user_id:
                    return jsonify({"message": "Apenas o criador do evento pode ver a lista de inscritos."}), FORBIDDEN_CODE
                               
                
                # Consulta para obter todos os utilizadores inscritos no evento com ID, username e data de inscrição
                query = """
                    SELECT u.id, u.username, i.data_hora_inscricao
                    FROM utilizador u
                    JOIN inscricao i ON u.id = i.id_utilizador
                    WHERE i.id_evento = %s AND i.estado = TRUE
                """
                cursor.execute(query, (event_id,))
                inscritos = cursor.fetchall()

                # Se não houver inscritos, retornar uma lista vazia
                if not inscritos:
                    return jsonify([]), OK_CODE

                # Formatando a resposta com os campos desejados
                inscritos_list = [{"id": i[0], "nome": i[1], "dataInscricao": i[2]} for i in inscritos]
                return jsonify(inscritos_list), OK_CODE

    except Exception as e:
        return jsonify({"message": "Erro ao listar inscritos.", "error": str(e)}), SERVER_ERROR




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)