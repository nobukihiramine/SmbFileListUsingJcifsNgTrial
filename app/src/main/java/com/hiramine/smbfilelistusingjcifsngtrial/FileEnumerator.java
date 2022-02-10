package com.hiramine.smbfilelistusingjcifsngtrial;

import android.os.Handler;
import android.os.Message;
import android.util.Log;

import java.net.MalformedURLException;
import java.net.NoRouteToHostException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import androidx.annotation.Nullable;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.smb.NtStatus;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.WinError;
import jcifs.util.transport.TransportException;

public class FileEnumerator
{
	// 定数
	private static final String LOGTAG = "FileEnumerator";

	public static final int RESULT_SUCCEEDED                 = 0;
	public static final int RESULT_FAILED_UNKNOWN_HOST       = 1;
	public static final int RESULT_FAILED_NO_ROUTE_TO_HOST   = 2;
	public static final int RESULT_FAILED_LOGON_FAILURE      = 3;
	public static final int RESULT_FAILED_BAD_NETWORK_NAME   = 4;
	public static final int RESULT_FAILED_NOT_FOUND          = 5;
	public static final int RESULT_FAILED_NOT_A_DIRECTORY    = 6;
	public static final int RESULT_FAILED_ACCESS_DENIED      = 7;
	public static final int RESULT_FAILED_FUNCTION_EXISTS    = 11;
	public static final int RESULT_FAILED_FUNCTION_LISTFILES = 12;
	public static final int RESULT_FAILED_UNKNOWN            = 99;

	// スレッドの作成と開始
	public void startEnumeration( Handler handler,
								  String strTargetPath,
								  String strUsername,
								  String strPassword )
	{
		Thread thread = new Thread( () -> threadfuncEnumerate( handler,
															   strTargetPath,
															   strUsername,
															   strPassword ) );
		thread.start();
	}

	// スレッド関数
	private void threadfuncEnumerate( Handler handler,
									  String strTargetPath,
									  String strUsername,
									  String strPassword )
	{
		Log.d( LOGTAG, "Enumeration thread started." );

		// 呼び出し元スレッドに返却する用のメッセージ変数の取得
		Message message = Message.obtain( handler );

		try
		{
			// CIFSContextは、再利用もしくは新規作成
			CIFSContext cifscontext;

			cifscontext = createCIFSContext( strUsername, strPassword );

			// SmbFileオブジェクト作成
			SmbFile smbfile = new SmbFile( strTargetPath, cifscontext );
			boolean bIsExists;
			try
			{
				bIsExists = smbfile.exists();
			}
			catch( SmbException e )
			{
				if( NtStatus.NT_STATUS_UNSUCCESSFUL == e.getNtStatus()
					&& e.getCause() instanceof UnknownHostException )
				{    // 不明なホスト
					message.what = RESULT_FAILED_UNKNOWN_HOST;
					message.obj = null;
					Log.w( LOGTAG, "Enumeration thread end. : Unknown host." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else if( NtStatus.NT_STATUS_UNSUCCESSFUL == e.getNtStatus()
						 && e.getCause() instanceof TransportException
						 && e.getCause().getCause() instanceof NoRouteToHostException )
				{    // ホストへのルートがない
					message.what = RESULT_FAILED_NO_ROUTE_TO_HOST;
					message.obj = null;
					Log.w( LOGTAG, "Enumeration thread end. : No route to host." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else if( NtStatus.NT_STATUS_LOGON_FAILURE == e.getNtStatus() )
				{    // SmbFile#exists()の結果「Logon failure」
					message.what = RESULT_FAILED_LOGON_FAILURE;
					message.obj = null;
					Log.w( LOGTAG, "Enumeration thread end. : Logon failure." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else if( NtStatus.NT_STATUS_BAD_NETWORK_NAME == e.getNtStatus() )
				{    // 不明なShare名
					message.what = RESULT_FAILED_BAD_NETWORK_NAME;
					message.obj = null;
					Log.w( LOGTAG, "Enumeration thread end. : Bad network name." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else
				{    // SmbFile#exists()の結果、原因不明で失敗
					message.what = RESULT_FAILED_FUNCTION_EXISTS;
					message.obj = null;
					Log.e( LOGTAG, "Enumeration thread end. : Function exists() failed." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
			}
			if( !bIsExists )
			{    // パスが存在しない
				message.what = RESULT_FAILED_NOT_FOUND;
				message.obj = null;
				Log.w( LOGTAG, "Enumeration thread end. : Not found." );
				return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
			}

			// 列挙
			SmbFile[] aSmbFile;
			try
			{
				aSmbFile = smbfile.listFiles();
			}
			catch( SmbException e )
			{
				if( NtStatus.NT_STATUS_NOT_A_DIRECTORY == e.getNtStatus() )
				{	// SmbFile#listFiles()の結果「Not a directory」
					message.what = RESULT_FAILED_NOT_A_DIRECTORY;
					message.obj = null;
					Log.w( LOGTAG, "Enumeration thread end. : Not a directory." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else if( WinError.ERROR_ACCESS_DENIED == e.getNtStatus() )
				{    // SmbFile#listFiles()の結果「Access denied」
					message.what = RESULT_FAILED_ACCESS_DENIED;
					message.obj = null;
					Log.w( LOGTAG, "Enumeration thread end. : Access denied." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else
				{    // SmbFile#listFiles()の結果、原因不明で失敗
					message.what = RESULT_FAILED_FUNCTION_LISTFILES;
					message.obj = null;
					Log.e( LOGTAG, "Enumeration thread end. : Function listFiles() failed." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
			}

			// SmbFileの配列を、FileItemのリストに変換
			List<FileItem> listFileItem = makeFileItemList( aSmbFile );

			// FileItemリストのソート
			sortFileItemList( listFileItem );

			// 成功
			message.what = RESULT_SUCCEEDED;
			message.obj = listFileItem;
			Log.d( LOGTAG, "Enumeration thread end. : Succeeded." );
		}
		catch( CIFSException | MalformedURLException e )
		{	// その他の失敗
			message.what = RESULT_FAILED_UNKNOWN;
			message.obj = null;
			Log.e( LOGTAG, "Enumeration thread end. : Failed with unknown cause." );
		}
		finally
		{
			// 呼び出し元スレッドにメッセージ返却
			handler.sendMessage( message );
		}
	}

	// CIFSContextの作成
	public static CIFSContext createCIFSContext( String strUsername,
												 String strPassword ) throws CIFSException
	{
		// SmbFileオブジェクト作成
		Properties prop = new Properties();
		prop.setProperty( "jcifs.smb.client.minVersion", "SMB202" );    // SMB1, SMB202
		prop.setProperty( "jcifs.smb.client.maxVersion", "SMB311" );    // SMB1, SMB311
		PropertyConfiguration     propconfig  = new PropertyConfiguration( prop );
		BaseContext               basecontext = new BaseContext( propconfig );
		NtlmPasswordAuthenticator authenticator;
		if( strUsername.isEmpty() )
		{    // ユーザー名が空の場合は、アノニマスで作成
			authenticator = new NtlmPasswordAuthenticator();
		}
		else
		{    // ユーザー名とパスワードを指定して作成
			authenticator = new NtlmPasswordAuthenticator( strUsername, strPassword );
		}
		return basecontext.withCredentials( authenticator );
	}

	// SmbFileの配列を、FileItemのリストに変換
	private static List<FileItem> makeFileItemList( @Nullable SmbFile[] aSmbFile )
	{
		if( null == aSmbFile )
		{    // nullの場合は、空のリストを返す。
			return new ArrayList<>();
		}

		List<FileItem> listFileItem = new ArrayList<>( aSmbFile.length );    // 数が多い場合も想定し、初めに領域確保。
		for( SmbFile smbfile : aSmbFile )
		{
			listFileItem.add( createFileItem( smbfile ) );
		}
		return listFileItem;
	}

	// SmbFileデータから、FileItemデータの作成
	public static FileItem createFileItem( SmbFile smbfile )
	{
		FileItem.Type type;
		try
		{
			// SmbFileのオブジェクトの種類
			// TYPE_FILESYSTEM(1) : ファイルかディレクトリ
			// TYPE_WORKGROUP(2) : ワークグループ
			// TYPE_SERVER(4) : サーバー
			// TYPE_SHARE(8) : 共有名（smb://server/share/directory/）
			// TYPE_NAMED_PIPE(16) : named pipe
			// TYPE_PRINTER(32) : プリンター
			// TYPE_COMM(64) : communications device
			int iType = smbfile.getType();
			switch( iType )
			{
				case SmbFile.TYPE_FILESYSTEM:
					if( smbfile.isDirectory() )
					{
						type = FileItem.Type.DIRECTORY;
					}
					else
					{
						type = FileItem.Type.FILE;
					}
					break;
				case SmbFile.TYPE_WORKGROUP:
					type = FileItem.Type.WORKGROUP;
					break;
				case SmbFile.TYPE_SERVER:
					type = FileItem.Type.SERVER;
					break;
				case SmbFile.TYPE_SHARE:
					type = FileItem.Type.SHARE;
					break;
				default:
					type = FileItem.Type.UNKNOWN;
					break;
			}
		}
		catch( SmbException e )
		{
			// ここに来るのは想定外。
			Log.e( LOGTAG, "SmbFile#getType() failed. : " + smbfile.getPath() );
			type = FileItem.Type.UNKNOWN;
		}

		long lLastModified = 0;
		try
		{
			lLastModified = smbfile.lastModified();
		}
		catch( SmbException e )
		{
			// ここに来るのは想定外。
			Log.e( LOGTAG, "SmbFile#lastModified() failed. : " + smbfile.getPath() );
		}

		long lFileSize = 0;
		if( FileItem.Type.FILE == type )
		{
			try
			{
				lFileSize = smbfile.length();
			}
			catch( SmbException e )
			{
				// タイプ確認し、ファイルの場合のみ処理実施しているので、ここに来るのは想定外。
				Log.e( LOGTAG, "SmbFile#length() failed. : " + smbfile.getPath() );
			}
		}

		return new FileItem( smbfile.getName().replace( "/", "" ),
							 smbfile.getPath(),
							 type,
							 lLastModified,
							 lFileSize );
	}

	// FileItemリストのソート
	public void sortFileItemList( List<FileItem> listFileItem )
	{
		Collections.sort( listFileItem, new FileItem.FileItemComparator() );
	}
}
