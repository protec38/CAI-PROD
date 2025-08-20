-- Apply ON DELETE CASCADE constraints (idempotent)
ALTER TABLE fiche_implique DROP CONSTRAINT IF EXISTS fiche_implique_evenement_id_fkey;
ALTER TABLE fiche_implique
  ADD CONSTRAINT fiche_implique_evenement_id_fkey
  FOREIGN KEY (evenement_id) REFERENCES evenement(id) ON DELETE CASCADE;

ALTER TABLE bagage DROP CONSTRAINT IF EXISTS bagage_fiche_id_fkey;
ALTER TABLE bagage
  ADD CONSTRAINT bagage_fiche_id_fkey
  FOREIGN KEY (fiche_id) REFERENCES fiche_implique(id) ON DELETE CASCADE;

ALTER TABLE bagage DROP CONSTRAINT IF EXISTS bagage_evenement_id_fkey;
ALTER TABLE bagage
  ADD CONSTRAINT bagage_evenement_id_fkey
  FOREIGN KEY (evenement_id) REFERENCES evenement(id) ON DELETE CASCADE;

ALTER TABLE animal DROP CONSTRAINT IF EXISTS animal_fiche_id_fkey;
ALTER TABLE animal
  ADD CONSTRAINT animal_fiche_id_fkey
  FOREIGN KEY (fiche_id) REFERENCES fiche_implique(id) ON DELETE CASCADE;

ALTER TABLE ticket DROP CONSTRAINT IF EXISTS ticket_evenement_id_fkey;
ALTER TABLE ticket
  ADD CONSTRAINT ticket_evenement_id_fkey
  FOREIGN KEY (evenement_id) REFERENCES evenement(id) ON DELETE CASCADE;

ALTER TABLE share_links DROP CONSTRAINT IF EXISTS share_links_evenement_id_fkey;
ALTER TABLE share_links
  ADD CONSTRAINT share_links_evenement_id_fkey
  FOREIGN KEY (evenement_id) REFERENCES evenement(id) ON DELETE CASCADE;
