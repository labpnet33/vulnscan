cd ~/vulnscan || exit

echo "===== $(date) ====="

# Fetch latest
git fetch origin main

# Force server to match repo exactly
git reset --hard origin/main
git clean -fd

# Restart service
sudo systemctl restart vulnscan

echo "Updated and restarted!"
