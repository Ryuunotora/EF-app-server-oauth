package pe.edu.cibertec.EF_app_server_oauth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pe.edu.cibertec.EF_app_server_oauth.model.Usuario;

public interface UsuarioRepository  extends JpaRepository<Usuario, Long> {

    Usuario findByCodigo(String codigo);
}
