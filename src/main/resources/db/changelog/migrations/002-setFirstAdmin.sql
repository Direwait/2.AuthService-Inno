CREATE OR REPLACE FUNCTION set_first_user_as_admin()
RETURNS TRIGGER AS $$
BEGIN
    IF (SELECT COUNT(*) FROM user_credential) = 0 THEN
        NEW.role := 'ADMIN';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_set_first_admin
    BEFORE INSERT ON user_credential
    FOR EACH ROW
    EXECUTE FUNCTION set_first_user_as_admin();