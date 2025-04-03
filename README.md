# 🔐 Microservice Authentication System

## Overview
A lightweight, scalable authentication microservice with:
- JWT token authentication
- Email verification
- Password reset flow
- Role-based permissions

## 🚀 Features

| Feature          | Description                          |
|------------------|--------------------------------------|
| JWT Auth         | Secure token-based authentication    |
| Email Verification | Double opt-in for new users         |
| Password Reset   | Secure token-based password recovery |
| Role Management  | Admin/Staff/User permissions        |

## 🛠️ Tech Stack
- **Python 3.10+**
- **Django 4.2+**
- **Django REST Framework**
- **PostgreSQL** (or SQLite for development)
- **Redis** (for token blacklisting)

## ⚙️ Installation

```bash
# Clone repository
git clone https://github.com/yourrepo/auth-microservice.git
cd auth-microservice

# Setup environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
