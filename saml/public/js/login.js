frappe.ready(async () => {
	const $email = $('#login_email')
	if ($email) {
		const { message: samlDomains } = await frappe.call({
			method: 'saml.saml.doctype.saml_login_key.saml_login_key.get_saml_domains',
		})

		// don't change login behavior if no SAML domains are configured
		if (samlDomains.length > 0) {
			$email.on('keyup', function () {
				const email = $(this).val()
				if (email && email.includes('@')) {
					const domain = email.split('@')[1]
					samlDomains.includes(domain) ? hideLoginFields() : showLoginFields()
				} else {
					showLoginFields()
				}
			})
		}
	}
})

function hideLoginFields() {
	$('.password-field').hide()
	$('.forgot-password-message').hide()
	$('.btn-login').hide()
	$('.login-divider').hide()
	$('.login-with-email-link').hide()
}

function showLoginFields() {
	$('.password-field').show()
	$('.forgot-password-message').show()
	$('.btn-login').show()
	$('.login-divider').show()
	$('.login-with-email-link').show()
}
