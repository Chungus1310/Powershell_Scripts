
# 🚀 PowerShell Scripts Collection

<div align="center">
  <img src="https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white" alt="PowerShell">
  <img src="https://img.shields.io/github/license/Chungus1310/Powershell_Scripts?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/github/repo-size/Chungus1310/Powershell_Scripts?style=for-the-badge" alt="Repo Size">
</div>

<br>

Welcome to my PowerShell scripts collection! This repository contains handy automation scripts for Windows system administration, productivity boosts, and utility functions. Feel free to use, modify, and contribute!

## 🌟 Featured Scripts

### 🔥 Current Scripts
| Script Name | Description | Usage Warning |
|-------------|-------------|---------------|
| [`remove_edge.ps1`](scripts/remove_edge.ps1) | Uninstalls Microsoft Edge and blocks automatic reinstallation | ⚠️ System modification |
| *More coming soon!* | | |


## 🛠️ Usage

```powershell
# 1. Download the script
# 2. Unblock the file (if downloaded from internet)
Unblock-File -Path .\remove_edge.ps1

# 3. Run as Administrator
Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `".\remove_edge.ps1`""
```

## 🛡️ Safety First!
- Always review scripts before running
- Create system restore points before making changes
- Test in non-production environments first

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing
Found a bug? Have an improvement? Contributions are welcome!
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request

## 📧 Contact
Have questions or suggestions? Open an issue or reach out!

<div align="center">
  <br>
  <p>Happy scripting! 💻</p>
  <img src="https://img.shields.io/github/stars/Chungus1310/Powershell_Scripts?style=social" alt="GitHub Stars">
</div>
