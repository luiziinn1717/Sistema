
from flask_wtf import FlaskForm
from wtforms import StringField, validators
from markupsafe import escape
from datetime import datetime
from decimal import Decimal, InvalidOperation

from flask import request

# Implementar validação de formulários
class PropostaForm(FlaskForm):
    numero_processo = StringField('Número Processo', 
        [validators.Length(min=1, max=100)])

# Sanitizar todos os inputs
def sanitize_input(data):
    if isinstance(data, str):
        return escape(data.strip())
    return data

def parse_date_safe(date_str, format='%Y-%m-%d'):
    try:
        return datetime.strptime(date_str, format).date()
    except (ValueError, TypeError):
        return None

def parse_decimal_safe(value_str):
    if value_str is None or value_str == '':
        return None
    try:
        # Sempre converte para string antes de replace
        clean_value = str(value_str).replace('.', '').replace(',', '.')
        return Decimal(clean_value)
    except (InvalidOperation, ValueError):
        return None
    
import pandas as pd
from datetime import datetime

def read_excel_file(file_path):
    """Lê um arquivo Excel e retorna um DataFrame do pandas."""
    try:
        df = pd.read_excel(file_path)
        return df
    except Exception as e:
        print(f"Erro ao ler o arquivo Excel: {e}")
        return None

def map_columns(df, column_mapping):
    """Mapeia as colunas do DataFrame de acordo com o dicionário de mapeamento."""
    df_mapped = df.copy()
    for original_col, standardized_col in column_mapping.items():
        if original_col in df_mapped.columns:
            df_mapped.rename(columns={original_col: standardized_col}, inplace=True)
    return df_mapped

def identify_missing_fields(df, required_fields):
    """Identifica campos que estão faltando no DataFrame em relação aos campos requeridos."""
    missing_fields = []
    for field in required_fields:
        if field not in df.columns:
            missing_fields.append(field)
    return missing_fields

def convert_date_columns(df, date_columns):
    """Converte colunas especificadas para o tipo datetime."""
    for col in date_columns:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors='coerce').dt.date
    return df

def convert_numeric_columns(df, numeric_columns):
    """Converte colunas especificadas para o tipo numérico."""
    for col in numeric_columns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    return df


