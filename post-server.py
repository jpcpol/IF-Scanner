from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/example/fake_url.php', methods=['POST'])
def receive_results():
    data = request.json
    if data:
        # Procesar los datos recibidos
        print("Datos recibidos:")
        print(data)
        return jsonify({'message': 'Datos recibidos correctamente'}), 200
    else:
        return jsonify({'error': 'No se recibieron datos en formato JSON'}), 400

if __name__ == '__main__':
    app.run(debug=True)