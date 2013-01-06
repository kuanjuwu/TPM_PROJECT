clear
export TESTSUITE_OWNER_SECRET=123
export TESTSUITE_SRK_SECRET=123
THEPATH=/root/testsuite-0.3/tcg/nv
LOGPATH=/root/testsuite-0.3/tcg/nv/log
NOW=$(date +"%F")
NOWT=$(date +"%F%T")
LOGFILE="tpm.log"
ERR_LOGFILE="tpm.err"
echo -e START TPM_STRESS_TEST: "$NOWT\n"
echo -e LOGFILE: "$LOGFILE & $ERR_LOGFILE\n"
cd  $THEPATH
        if [ -e "$LOGPATH/$LOGFILE" ]
               then
                echo "$LOGFILE & $ERR_LOGFILE Already Exist"
                date >> $LOGPATH/$LOGFILE && date >> $LOGPATH/$ERR_LOGFILE
                ./go_test >>$LOGPATH/$LOGFILE 2>>$LOGPATH/$ERR_LOGFILE
        else
                echo "Creating $LOGFILE & $ERR_LOGFILE"
                touch $LOGPATH/$LOGFILE
                date > $LOGPATH/$LOGFILE && date > $LOGPATH/$ERR_LOGFILE
               ./go_test >$LOGPATH/$LOGFILE 2>$LOGPATH/$ERR_LOGFILE
        fi
\end{lstlisting}
