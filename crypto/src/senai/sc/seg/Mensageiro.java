package senai.sc.seg;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */


import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.ArrayList;

public interface Mensageiro extends Remote {

        public PublicKey getChavePub() throws RemoteException;
        public boolean gravaChaveSim(byte[] chaveSim) throws RemoteException;
        public byte[] gravaFila(byte[] nomeFila, byte[] mensagem) throws RemoteException;
        public byte[] deletaFila(byte[] nomeFila) throws RemoteException;
        public ArrayList lerFila(byte[] nomefilas) throws RemoteException;
}
