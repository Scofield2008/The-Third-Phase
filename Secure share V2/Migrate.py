#!/usr/bin/env python3
"""
Database Migration Script for SecureShare Enhanced Edition
Upgrades existing database to support new features
"""
import sqlite3
import os
import shutil
from datetime import datetime

def backup_database(db_path='secureshare.db'):
    """Create backup of existing database"""
    if not os.path.exists(db_path):
        print(f"✓ No existing database found at {db_path}")
        return None
    
    backup_dir = 'backups'
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(backup_dir, f'secureshare_backup_{timestamp}.db')
    
    shutil.copy2(db_path, backup_path)
    print(f"✓ Database backed up to: {backup_path}")
    return backup_path

def check_column_exists(cursor, table_name, column_name):
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns

def migrate_database(db_path='secureshare.db'):
    """Migrate database to new schema"""
    print("\n" + "="*60)
    print("SecureShare Database Migration")
    print("="*60 + "\n")
    
    # Backup first
    backup_path = backup_database(db_path)
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        print("Checking database schema...")
        
        # Get current schema
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        if 'files' not in tables:
            print("✓ No existing files table, creating fresh database...")
            create_fresh_database(cursor)
            conn.commit()
            print("✓ Fresh database created successfully")
            return
        
        print("✓ Found existing files table, checking for missing columns...")
        
        # List of new columns to add
        new_columns = [
            ('original_filename', 'TEXT NOT NULL DEFAULT ""'),
            ('mime_type', 'TEXT'),
            ('virus_scan_status', 'TEXT DEFAULT "pending"'),
            ('virus_scan_result', 'TEXT'),
            ('has_preview', 'BOOLEAN DEFAULT 0'),
            ('preview_path', 'TEXT')
        ]
        
        migrations_applied = 0
        
        for column_name, column_def in new_columns:
            if not check_column_exists(cursor, 'files', column_name):
                print(f"  → Adding column: {column_name}")
                
                # Special handling for original_filename
                if column_name == 'original_filename':
                    # First add the column allowing NULL
                    cursor.execute(f'ALTER TABLE files ADD COLUMN {column_name} TEXT')
                    # Update existing rows to use filename
                    cursor.execute('UPDATE files SET original_filename = filename WHERE original_filename IS NULL')
                else:
                    cursor.execute(f'ALTER TABLE files ADD COLUMN {column_name} {column_def}')
                
                migrations_applied += 1
            else:
                print(f"  ✓ Column exists: {column_name}")
        
        # Create indexes
        print("\nCreating indexes...")
        indexes = [
            ('idx_expiry', 'files', 'expiry'),
            ('idx_file_id', 'audit_logs', 'file_id'),
            ('idx_virus_scan', 'files', 'virus_scan_status'),
            ('idx_upload_time', 'files', 'upload_time'),
            ('idx_mime_type', 'files', 'mime_type')
        ]
        
        for idx_name, table_name, column_name in indexes:
            try:
                cursor.execute(f'CREATE INDEX IF NOT EXISTS {idx_name} ON {table_name}({column_name})')
                print(f"  ✓ Index created: {idx_name}")
            except Exception as e:
                print(f"  ⚠ Index {idx_name} already exists or error: {e}")
        
        # Check audit_logs table
        if 'audit_logs' in tables:
            if not check_column_exists(cursor, 'audit_logs', 'user_agent'):
                print("\n  → Adding user_agent column to audit_logs")
                cursor.execute('ALTER TABLE audit_logs ADD COLUMN user_agent TEXT')
                migrations_applied += 1
        
        conn.commit()
        
        print("\n" + "="*60)
        if migrations_applied > 0:
            print(f"✓ Migration completed successfully!")
            print(f"✓ Applied {migrations_applied} schema changes")
        else:
            print("✓ Database schema is already up to date")
        print("="*60 + "\n")
        
        # Show statistics
        cursor.execute('SELECT COUNT(*) FROM files')
        file_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM audit_logs')
        log_count = cursor.fetchone()[0]
        
        print(f"Database Statistics:")
        print(f"  Files: {file_count}")
        print(f"  Audit Logs: {log_count}")
        if backup_path:
            print(f"  Backup: {backup_path}")
        print()
        
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        print(f"✓ Your data is safe in the backup: {backup_path}")
        conn.rollback()
        raise
    finally:
        conn.close()

def create_fresh_database(cursor):
    """Create fresh database with full schema"""
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            expiry DATETIME NOT NULL,
            max_downloads INTEGER NOT NULL,
            current_downloads INTEGER DEFAULT 0,
            salt TEXT,
            iv TEXT NOT NULL,
            password_protected BOOLEAN DEFAULT 0,
            rsa_public_key TEXT,
            encrypted_aes_key TEXT,
            rsa_private_key_hash TEXT,
            upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_size INTEGER DEFAULT 0,
            mime_type TEXT,
            virus_scan_status TEXT DEFAULT 'pending',
            virus_scan_result TEXT,
            has_preview BOOLEAN DEFAULT 0,
            preview_path TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT,
            action TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_agent TEXT
        )
    ''')
    
    # Create all indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_expiry ON files(expiry)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_id ON audit_logs(file_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_virus_scan ON files(virus_scan_status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_upload_time ON files(upload_time)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_mime_type ON files(mime_type)')

def verify_migration(db_path='secureshare.db'):
    """Verify migration was successful"""
    print("Verifying migration...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check files table schema
        cursor.execute("PRAGMA table_info(files)")
        columns = {row[1]: row[2] for row in cursor.fetchall()}
        
        required_columns = [
            'id', 'filename', 'original_filename', 'expiry', 'max_downloads',
            'current_downloads', 'salt', 'iv', 'password_protected',
            'rsa_public_key', 'encrypted_aes_key', 'rsa_private_key_hash',
            'upload_time', 'file_size', 'mime_type', 'virus_scan_status',
            'virus_scan_result', 'has_preview', 'preview_path'
        ]
        
        missing_columns = [col for col in required_columns if col not in columns]
        
        if missing_columns:
            print(f"✗ Missing columns: {', '.join(missing_columns)}")
            return False
        
        # Check indexes
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='files'")
        indexes = [row[0] for row in cursor.fetchall()]
        
        required_indexes = ['idx_expiry', 'idx_virus_scan']
        missing_indexes = [idx for idx in required_indexes if idx not in indexes]
        
        if missing_indexes:
            print(f"⚠ Missing indexes: {', '.join(missing_indexes)}")
            # This is a warning, not a failure
        
        print("✓ Migration verification passed")
        return True
        
    except Exception as e:
        print(f"✗ Verification failed: {e}")
        return False
    finally:
        conn.close()

if __name__ == '__main__':
    import sys
    
    print("""
╔═══════════════════════════════════════════════════════════╗
║       SecureShare Enhanced Database Migration Tool        ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Check if database exists
    db_path = 'secureshare.db'
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    
    if not os.path.exists(db_path) and db_path == 'secureshare.db':
        print("No existing database found. A new one will be created on first run.")
        print("You can safely run the application now.")
        sys.exit(0)
    
    try:
        # Run migration
        migrate_database(db_path)
        
        # Verify
        if verify_migration(db_path):
            print("\n✓ Your database is ready for SecureShare Enhanced Edition!")
            print("✓ You can now run: python app.py")
        else:
            print("\n⚠ Migration completed but verification found issues")
            print("⚠ Check the output above for details")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠ Migration cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        print("✗ Please restore from backup if needed")
        sys.exit(1)