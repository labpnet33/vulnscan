cd ~/vulnscan
git add .
git commit -m "${1:-Update vulnscan}"
git push origin main
sudo systemctl restart vulnscan
echo "Pushed and restarted!"
sudo systemctl unmask apache2
sudo systemctl enable apache2
sudo systemctl start apache2
sudo systemctl status apache2
echo "Apache restarted"
