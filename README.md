# 🚩 CTF Platform - Zero-Cost Admin-Driven Platform

A complete Capture The Flag (CTF) web platform that runs entirely on JSON files with no database requirements. Perfect for hosting CTF competitions on free platforms like Railway, Render, or Replit.

## ✨ Features

### 🎮 User Features
- **User Registration & Login** with session management
- **Challenge Categories** (Web, Crypto, Pwn, Rev, Misc, Forensics)
- **Dynamic Scoring** based on solve count
- **Team Mode** support with team leaderboards
- **Real-time Scoreboard** with individual and team rankings
- **Challenge Prerequisites** and hint system
- **Responsive Design** with Bootstrap 5

### 🛠️ Admin Features
- **Complete Admin Panel** for CTF management
- **Challenge Management** - Add/Edit/Delete challenges
- **User Management** - View users and login logs
- **Configuration Panel** - Toggle CTF settings live
- **Announcements System** - Post updates to all users
- **Submission Logs** - View all flag attempts
- **CTF Reset** - Clean slate for new competitions
- **Telegram Integration** - Export results to Telegram

### 🏗️ Technical Features
- **JSON-Based Storage** - No database required
- **Flask Backend** with session authentication
- **Rate Limiting** protection
- **Security Features** - Password hashing, CSRF protection
- **Docker Ready** - Easy deployment
- **Zero-Cost Hosting** - Runs on free platforms

## 🚀 Quick Start
### 1. Create Project Structure
```powershell
# Run this PowerShell script to create all directories and files
New-Item -ItemType Directory -Path "ctf_platform" -Force
Set-Location "ctf_platform"

# Create directories
New-Item -ItemType Directory -Path "templates/admin", "static/css", "static/js", "data" -Force

# Create files (then populate with provided code)
New-Item -ItemType File -Path "app.py", "requirements.txt", "README.md" -Force
