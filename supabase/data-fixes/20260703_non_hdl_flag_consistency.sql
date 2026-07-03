-- Data-hygiene fix (applied to project pjuwipjyxzxlmhebzdct on 2026-07-03).
--
-- Problem: the "Non-HDL-Cholesterin" marker had 8 rows for the same person but only one
-- (id 1007, 167 mg/dl) carried a reference range (ref_high = 130) and a flag ('high').
-- The other rows had flag = NULL, so the two most elevated historical values (181 and 159
-- mg/dl) — both ABOVE the 130 threshold the lab itself used — were displayed as "normal".
--
-- Fix: propagate the marker's OWN existing threshold (130) to all its rows and derive the flag
-- consistently. This introduces no new clinical judgement — it only makes the record internally
-- consistent with what the lab already recorded — and moves in the safe direction (surfacing
-- elevated values rather than hiding them). Confirm the 130 target with the treating doctor.
UPDATE lab_results
SET ref_high = 130, ref_low = NULL,
    flag = CASE WHEN value_num > 130 THEN 'high' ELSE 'normal' END
WHERE marker = 'Non-HDL-Cholesterin' AND value_num IS NOT NULL;

-- Result: 132, 159, 167, 181 -> 'high';  95, 105, 120, 95 -> 'normal'.
--
-- Rollback (restore the pre-fix state exactly):
--   UPDATE lab_results SET ref_high = NULL, ref_low = NULL, flag = NULL
--     WHERE marker = 'Non-HDL-Cholesterin' AND id IN (618,665,752,286,43,195);
--   UPDATE lab_results SET ref_high = NULL, flag = 'normal'
--     WHERE marker = 'Non-HDL-Cholesterin' AND id = 838;
--   UPDATE lab_results SET ref_high = 130, ref_low = NULL, flag = 'high'
--     WHERE marker = 'Non-HDL-Cholesterin' AND id = 1007;
