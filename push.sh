cd ~/vulnscan
git add .
git commit -m "${1:-Update vulnscan}"
git push origin main
sudo systemctl restart vulnscan
echo "Pushed and restarted!"
