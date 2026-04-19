import os
import secrets

# API keys — set via environment variables in production
# Generate a key with: python3 -c "import secrets; print('mhf_' + secrets.token_hex(24))"
CLIENT_API_KEY  = os.getenv('MAHORAGA_CLIENT_KEY',  'mhf_dev_client_key_change_in_prod')
ADMIN_API_KEY   = os.getenv('MAHORAGA_ADMIN_KEY',   'mhf_dev_admin_key_change_in_prod')

DB_PATH         = os.getenv('DB_PATH',    'federation.db')
MODEL_PATH      = os.getenv('MODEL_PATH', 'models/global_model.pkl')
LOG_LEVEL       = os.getenv('LOG_LEVEL',  'INFO')

# Retrain when this many new vectors have arrived since last train
RETRAIN_THRESHOLD = int(os.getenv('RETRAIN_THRESHOLD', '50'))

# Daily retrain schedule (24h cron)
RETRAIN_HOUR   = int(os.getenv('RETRAIN_HOUR',   '2'))
RETRAIN_MINUTE = int(os.getenv('RETRAIN_MINUTE', '0'))
