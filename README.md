1. Create a virtual environment:

# Windows
py -m venv env

# macOS/Linux
python3 -m venv env

2. Activate the virtual environment:

# Windows (Command Prompt)
env\Scripts\activate

# Windows (PowerShell)
.\env\Scripts\Activate.ps1

# macOS/Linux
source env/bin/activate

3. Install Dependencies:

pip install -r requirements.txt

4. Train or Retrain the Model:

python train_model.py

5. Run the Web App (Local Development):

python app.py

6. Run the Web App (Production via Gunicorn):

gunicorn app:app