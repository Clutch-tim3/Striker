#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "▶ Installing Node dependencies..."
cd "$ROOT" && npm install

echo "▶ Checking Python dependencies..."
pip3 install -q -r "$ROOT/python/requirements.txt"

echo "▶ Creating model stubs if missing..."
python3 - <<'EOF'
import os, pickle
from sklearn.ensemble import IsolationForest, RandomForestClassifier

models_dir = os.path.join(os.path.dirname(os.path.abspath('.')), 'models')
os.makedirs('models', exist_ok=True)

if not os.path.exists('models/anomaly_model.pkl'):
    model = IsolationForest(contamination=0.05, random_state=42)
    with open('models/anomaly_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    print('  Created models/anomaly_model.pkl (untrained stub)')

if not os.path.exists('models/behaviour_classifier.pkl'):
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    with open('models/behaviour_classifier.pkl', 'wb') as f:
        pickle.dump(model, f)
    print('  Created models/behaviour_classifier.pkl (untrained stub)')
EOF

echo "▶ Launching Mahoraga in dev mode..."
cd "$ROOT" && npx electron .
