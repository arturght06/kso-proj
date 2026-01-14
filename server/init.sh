sudo apt install python3.10-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

sudo usermod -aG docker $USER


 sudo apt install python3-pip; python3 -m venv .venv; .venv/bin/python -m pip install -r ~/kso-proj/server/requirements.txt; .venv/bin/python agent.py