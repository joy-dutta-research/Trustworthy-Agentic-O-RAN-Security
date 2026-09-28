# Required run metadata

Use the model name and reasoning/mode label exactly as shown in your interface.
Do not invent a version, mode, seed, or temperature. If a setting is unavailable,
list it in unavailable_settings (an array of strings). If you cannot observe the
model name or mode, put not_available in that field and name the unavailable
field in unavailable_settings. The operator may supply the observed labels;
do not infer them from your own generated claims. Record the UTC run date
as YYYY-MM-DD. tools_used is an array listing any permitted local attachment,
JSON, arithmetic, or output-formatting tools actually used; use [] if none.
If the service cannot prevent forbidden access or isolate prior context, record that failure
and do not describe the run as blinded. Save the unedited first response and
record any timeout, truncation, refusal, or format failure outside the result.
Two model runs do not replace human review and may share correlated biases.
