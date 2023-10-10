package org.wso2.carbon.identity.scim2.common.DAO;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationMgtUtil;
import org.wso2.carbon.identity.application.mgt.dao.impl.ApplicationMgtDBQueries;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.charon3.core.schema.SCIMConstants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * JDBC based Data Access layer for asynchronous SCIM operations.
 */
public class BulkDAO {
    private static final Log log = LogFactory.getLog(GroupDAO.class);

    public void addAsyncOperation(String asyncOpID, int tenantId, String status, String message)
            throws SQLException {
        Connection connection = IdentityDatabaseUtil.getUserDBConnection();
        PreparedStatement prepStmt = null;

        try {
            prepStmt = connection.prepareStatement(SQLQueries.ADD_ASYNC_OPERATION_SQL);
            prepStmt.setString(1, asyncOpID);
            prepStmt.setInt(2, tenantId);
            prepStmt.setString(3, status);
            prepStmt.setString(4, message);

            prepStmt.executeQuery();
            connection.commit();

        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    public Map<String, String> getAsyncOperation(String asyncOpID) throws SQLException {

        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        Connection connection = null;
        Map<String, String> permissions = new HashMap<>();
//        try {
//
//            connection = IdentityDatabaseUtil.getUserDBConnection(false);
//            prepStmt = connection.prepareStatement(ApplicationMgtDBQueries.LOAD_UM_PERMISSIONS);
//            prepStmt.setString(1, "%" + ApplicationMgtUtil.getApplicationPermissionPath() + "%");
//            resultSet = prepStmt.executeQuery();
//            while (resultSet.next()) {
//                String umId = resultSet.getString(1);
//                String permission = resultSet.getString(2);
//                if (permission.contains(ApplicationMgtUtil.getApplicationPermissionPath() +
//                        ApplicationMgtUtil.PATH_CONSTANT + applicationName.toLowerCase())) {
//                    permissions.put(umId, permission);
//                }
//            }
//        } finally {
//            IdentityDatabaseUtil.closeResultSet(resultSet);
//            IdentityDatabaseUtil.closeStatement(prepStmt);
//            IdentityDatabaseUtil.closeConnection(connection);
//        }
        return permissions;
    }

}

