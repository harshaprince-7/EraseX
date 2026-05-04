# Traze Zero – Secure Data Erasure System

## Overview

Traze Zero is a secure data erasure system designed to permanently wipe data from storage devices such as HDDs and SSDs. The system ensures that deleted data cannot be recovered and provides verifiable audit logs for enterprise-level compliance and security requirements.

---

## Tech Stack

* Frontend: React.js, Tauri
* Backend: Rust
* Database: PostgreSQL
* Authentication: JWT

---

## System Architecture

The system follows a modular architecture:

Frontend (React + Tauri) → Backend Services → Storage Devices → PostgreSQL

* Frontend handles user interaction and device selection
* Backend performs secure data wiping operations
* Database stores audit logs and operation history

---

## Core Features

* Secure and irreversible data erasure for HDD and SSD
* Audit logging for all operations
* Cross-platform desktop application
* Authentication and access control using JWT
* High-performance execution for large data volumes

---

## Data Security Approach

The system ensures secure deletion by overwriting storage sectors, making data recovery practically impossible. All operations are logged to maintain traceability and accountability.

---

## Database Design

### Audit Logs Table

* log_id (Primary Key)
* operation_type
* timestamp
* status
* device_info

### Users Table

* user_id (Primary Key)
* username
* password

---

## How to Run

### Frontend

1. Navigate to the frontend directory
2. Install dependencies:

   ```bash
   npm install
   ```
3. Start the application:

   ```bash
   npm run tauri dev
   ```

### Backend

1. Configure the data erasure module
2. Set up PostgreSQL connection
3. Run backend services

---

## Challenges Faced

* Implementing secure and reliable data wiping mechanisms
* Ensuring system performance for large storage devices
* Designing audit logging for traceability

---

## Key Learnings

* Understanding secure data deletion techniques
* Building cross-platform desktop applications
* Integrating authentication and audit logging
* Handling system-level operations

---

## Future Improvements

* Add role-based access control
* Enhance reporting and analytics for audit logs
* Improve scalability for enterprise environments

---

## Why this Project

## This project demonstrates the ability to work on security-focused systems, implement reliable backend processes, and design applications that handle critical data operations.
