# KAMEL Antivirus
- A layered approach making use of both signature based and heuristic based detection, this antivirus is lightweight and supports directory uploads as well

## Contributors
1. Elizabeth Jees Tharayil
2. Kavimalar Subbiah
3. Mercia Melvin P

## How to run the program?
1. **Download this GitHub repository**
	- Either Clone the repository
		```
		git clone https://github.com/KavimalarSubbiah/Antivirus
		```
	- Or download and extract the zip archive of the repository.

2. **Download & Install requirements**
	- Ensure that you have Python 3 installed.
        - Ensure that you have gcc installed
	- Open terminal in the Repository folder on your local machine.
	- Run the following command to install requirements.
		```
		pip3 install -r requirements.txt
 		```
3. **Compile engine.c using the following command**
   - compile engine.c using
     ```
     gcc engine.c -o engine -lyara
     ```
 - An executable file will be formed
4. **Run gui.py**
   - Rub gui.py using the following command
     ```
     python3 gui.py
     ```

## References
- [Yara Rules for malware detection](https://ieeexplore.ieee.org/abstract/document/10549308)
- [Book for Antivirus Bypass techniques](https://books.google.co.in/books?hl=en&lr=&id=Gpw3EAAAQBAJ&oi=fnd&pg=PP1&dq=yara+rules+for+antivirus&ots=nw97Xbqbmn&sig=JZdT3Pnj8gBzrZIDqPGK1eGcF6Y&redir_esc=y#v=onepage&q=yara%20rules%20for%20antivirus&f=false)
- [Multi-layered defense architecture against ransomware](https://www.researchgate.net/profile/Manveer-Patyal/publication/315471509_Multi-layered_defense_architecture_against_ransomware/links/58d13233aca272380eca20ad/Multi-layered-defense-architecture-against-ransomware.pdf)
- [Random Forest Documentation](http://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)
- [About Random Forest Algorithm](https://www.javatpoint.com/machine-learning-random-forest-algorithm)
- [Extra Trees Classifier](https://www.geeksforgeeks.org/ml-extra-tree-classifier-for-feature-selection/)
