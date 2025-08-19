from app import create_app
app = create_app()
if __name__ == "__main__":
    # Dev command only; production should use: gunicorn 'run:app' --workers 4 --threads 2 --bind 0.0.0.0:5000
    app.run(host="0.0.0.0", port=5000, debug=False)
