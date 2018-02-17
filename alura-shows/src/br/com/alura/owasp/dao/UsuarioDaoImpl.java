package br.com.alura.owasp.dao;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Repository;

import br.com.alura.owasp.model.Usuario;

@Repository
public class UsuarioDaoImpl implements UsuarioDao {
	
	@PersistenceContext
	private EntityManager manager;


	public void salva(Usuario usuario) {
		encriptaSenha(usuario);
		manager.persist(usuario);
	}

	private void encriptaSenha(Usuario usuario) {
		String salto = BCrypt.gensalt();
		String senhaEncriptada = BCrypt.hashpw(usuario.getSenha(), salto);
		usuario.setSenha(senhaEncriptada);
	}

	public Usuario procuraUsuario(Usuario usuario) {
		TypedQuery<Usuario> query = manager.createQuery("select u from Usuario u where u.email=:email",Usuario.class);
		query.setParameter("email", usuario.getEmail());
		Usuario usuarioEncontrado = query.getResultList().stream().findFirst().orElse(null);
		if(validaSenha(usuario,usuarioEncontrado)) {
			return usuarioEncontrado;
		}
		return null;
	}

	private boolean validaSenha(Usuario usuario, Usuario usuarioEncontrado) {
		if(usuarioEncontrado == null) {
			return false;
		}
		return BCrypt.checkpw(usuario.getSenha(), usuarioEncontrado.getSenha());
	}
}
