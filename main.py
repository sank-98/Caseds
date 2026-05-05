# Updated main.py

from caseds.models.schemas import RawInput, ThreatAnalysisResponse, HealthResponse

# Call pipeline functions and compute processing time
raw_input = RawInput()  # Example instantiation
normalized = caseds.pipeline.input_layer.normalizer.normalize(raw_input)
features = caseds.pipeline.feature_extraction.extract_bundle(normalized)
processing_time_ms = ... # compute processing time here
result = caseds.pipeline.scoring.score_threat(normalized, features)

# return appropriate ThreatAnalysisResponse
response = ThreatAnalysisResponse(result=result, processing_time=processing_time_ms)

