from misago.auth import sign_user_in


def run(request, user):
	return sign_user_in(request, user)
	