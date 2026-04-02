cd ~/vulnscan
git pull origin main
sudo systemctl restart vulnscan
echo "Updated and restarted!"
sudo systemctl restart apache2
