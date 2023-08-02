from flask import jsonify
import pandas as pd
import joblib



def predict_vuln_validity(severity, v_type, description_length, attack_length, evidence_length, source_length,
                          name_length):
    # Load the model and scalers
    model = joblib.load('model.pkl')
    scaler = joblib.load('scaler.pkl')
    label_encoder_severity = joblib.load('label_encoder_severity.pkl')
    label_encoder_type = joblib.load('label_encoder_type.pkl')

    # Transform severity and v_type using label encoders
    severity_encoded = label_encoder_severity.transform([severity])[0]
    v_type_encoded = label_encoder_type.transform([v_type])[0]

    # Define the columns names
    columns = ['severity', 'type', 'description_length', 'attack_length', 'evidence_length', 'source_length', 'name_length']

    # Scale features
    # Create a DataFrame with the defined feature names
    features_to_scale = pd.DataFrame([[severity_encoded, v_type_encoded, description_length, attack_length,
                                       evidence_length, source_length, name_length]], columns=columns)

    # Scale features
    features_scaled = scaler.transform(features_to_scale)

    # Make a prediction
    prediction = model.predict(features_scaled)[0]

    # Get probability for true positive class
    probability = model.predict_proba(features_scaled)[0][1]

    return jsonify({
        'prediction': 'true_positive' if prediction == 1 else 'false_positive',
        'probability': probability * 100
    })



