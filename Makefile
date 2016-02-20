build-and-deploy:
	docker build -t certificate-transparency-watch-docker-ct-watch-registry.bintray.io/hs-certificate-transparency .
	docker push certificate-transparency-watch-docker-ct-watch-registry.bintray.io/hs-certificate-transparency
